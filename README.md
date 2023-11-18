# buildx-runner a tool to inspect failed buildx runs

Docker buildx is a great tool, but for now it is quite cumbersome when it comes
to debugging a failed build, the best so far is to insert an additional target
right before the line where the build fails, and then start the created image
as an interactive container.

Since this is a bit cumbersome, specially when used in a ci context
buildx-runner automates this for you, so basically it just runs docker buildx
normally, and if the build fails it will determine the failed line, insert a
new target, will build the previous target and give you the hash of the just
created image, you can then start it as a container an debug.

## Usage

```
buildx-runner -l <log-level> <... all the usual docker buildx arguments(without docker buildx build)>
```

for example:

```
buildx-runner -l info -f Dockerfile-Test .
```
