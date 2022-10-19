#!/usr/bin/python3 -u
import os
import time
import re
import sys
import io
import shutil
import tarfile
import tempfile
import logging
import subprocess
import argparse
from typing import List


logger = logging.getLogger(__name__)

def get_context_from_stdin():
    data = sys.stdin.buffer.read()
    io_bytes = io.BytesIO(data)
    tar = tarfile.open(fileobj=io_bytes, mode='r')
    return tar

def get_file_from_tar(tar,filename):
    file_content_byte = None
    for name in tar.getnames():
        if filename in name: 
            file_content_byte = tar.extractfile(name).read()
    return file_content_byte

def run_docker_buildx(dockerfile:str,path:str,docker_args:List[str],quiet:bool=False,keep:bool=False):
    os.environ['PYTHONUNBUFFERED'] = '1'
    tempdir = None
    if path == '-':
        tar = get_context_from_stdin()
        tempdir = tempfile.mkdtemp()
        tar.extractall(tempdir)
        path = tempdir
    try:
        proc = subprocess.Popen(
            ['docker','buildx','build','--progress=plain','-f',dockerfile,path]+list(docker_args),
           stdout=subprocess.PIPE,
           stderr=subprocess.PIPE,
        )
        logger.info('Started docker buildx run with %s',docker_args)
        failed_stmt_pattern = re.compile('^> \[(.*) [0-9]*/[0-9]*\] (.*):$')
        build_target = None
        failed_cmd = None
        while proc.poll() is None:
            for line in iter(proc.stderr.readline,b''):
                decoded_line = line.decode('utf-8').strip()
                if not quiet:
                    print(decoded_line,flush=True)
                if decoded_line.startswith('>'):
                    match = failed_stmt_pattern.match(decoded_line)
                    if match is not None:
                        build_target = match.group(1)
                        failed_cmd = match.group(2)
                        failed_cmd = re.sub(' +',' ',failed_cmd)
        returncode = proc.returncode
        logger.info('Normal docker buildx run finished with %s',returncode)
        if returncode != 0:
            # replace multiple whitespaces with one
            failed_cmd = re.sub('\s+',' ',failed_cmd)
            if build_target is None or failed_cmd is None:
                raise Exception(f'Failed getting the target {build_target}:{failed_cmd}')
            env_pattern = re.compile('^ENV ([^ ]*) (.*)$')
            gen_pattern = re.compile('\\\\\$([A-Za-z0-9_]*)')
            vars = {}
            added_target = False
            tmpddockerfile = tempfile.NamedTemporaryFile(mode='w',dir=path,delete=False)
            if tempdir is None:
                dockerfile_path = dockerfile
            else:
                dockerfile_path = os.path.join(tempdir,dockerfile)
            with open(dockerfile_path,'r') as _file:
                orig_dockerfile_content = _file.read()
                dockerfile_content = re.sub(r" *\\ *\r?\n\n? *"," ",orig_dockerfile_content)
            for line_nr,line in enumerate(dockerfile_content.splitlines()):
                if not line.strip():
                    continue
                match = env_pattern.match(line)
                if match is not None:
                    var = match.group(1) 
                    val = match.group(2) 
                    vars[var] = val.strip()
                else:
                    new_line = line
                    for var,val in vars.items():
                        new_line = re.sub(f'\${{?{var}}}?',val,new_line).strip()

                    # replace multiple whitespaces with one
                    new_line = re.sub('\s+',' ',new_line)
                    # replace remaining variables with some wildcard
                    new_line = gen_pattern.sub('[^ ]*',re.escape(new_line))
                    logger.debug('LINE: %s',new_line)
                    match = re.match(new_line,failed_cmd)
                    if match and not added_target:
                        added_target = True
                        logger.info('Added new target at line %s - %s ---- %s',line_nr,new_line,failed_cmd)
                        tmpddockerfile.write(f'FROM {build_target}\n')
                    elif match:
                        raise Exception('Matched multiple lines')
                tmpddockerfile.write(line)
                tmpddockerfile.write('\n')

            tmpddockerfile.flush()
            if added_target:
                cmd = [
                    'docker',
                    'buildx',
                    'build',
                    f'--target={build_target}',
                    '--progress=plain',
                    '-f',tmpddockerfile.name,
                    path,
                ]
                skip_next = False
                for item in docker_args:
                    if item.startswith('--output'):
                        if not item.startswith('--output='):
                            skip_next = True
                        cmd.append('--output')
                        cmd.append('type=docker')
                    elif not skip_next:
                        cmd.append(item)
                    else:
                        skip_next = False

                logger.info('Starting modified docker with %s',cmd)
                tmpddockerfile.close()
                proc = subprocess.Popen(
                   cmd,
                   stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE,
                   env=os.environ,
                )
                sha_pattern = re.compile('^#[0-9]* writing image sha256:([a-z0-9]*) done')
                sha256 = None
                while proc.poll() is None:
                    for line in iter(proc.stderr.readline,b''):
                        decoded_line = line.decode('utf-8').strip()
                        match = sha_pattern.match(decoded_line)
                        if match is not None:
                            sha256 = match.group(1)
                        if not quiet:
                            print(decoded_line,flush=True)
                        if decoded_line.startswith('>'):
                            match = failed_stmt_pattern.match(decoded_line)
                            if match is not None:
                                build_target = match.group(1)
                                failed_cmd = match.group(2)
                                failed_cmd = re.sub(' +',' ',failed_cmd)
                stdout,stderr = proc.communicate()
                if sha256:
                    os.remove(tmpddockerfile.name)
                    print(f'Debug image ready with sha256: {sha256}')
                else:
                    print('Failed getting the sha256 %s'%decoded_stderr.splitlines()[-1])
                    print('Run cmd: ' + (' '.join(cmd)))
            else:
                logger.error('Failed to find failed line for %s',failed_cmd)
    finally:
        if tempdir is not None:
            shutil.rmtree(tempdir)
    return returncode

def make_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('path',default='.', help='specify the docker context')
    parser.add_argument('-f','--dockerfile',default='Dockerfile', help='path to the dockerfile')
    parser.add_argument('-q','--quiet', dest='quiet', action='store_true', help='silence the docker output')
    parser.add_argument('-k','--keep', dest='keep', action='store_true', help='keep the modified dockerfile')
    parser.add_argument('-l','--log-level', dest='log_level', default='WARNING',help='set log level')
    parser.add_argument('docker_args',nargs=argparse.REMAINDER,help='additional docker args')
    return parser

def main():
    parser = make_parser()
    args = parser.parse_args()
    kwargs = vars(args)
    logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s',level=kwargs.pop('log_level').upper())
    returncode = run_docker_buildx(**kwargs)
    sys.exit(returncode)
    

if __name__ == '__main__':
    main()
