FROM gitpod/workspace-full

# add your tools here ...

# Install custom tools, runtime, etc.

RUN bash -c ". /home/gitpod/.sdkman/bin/sdkman-init.sh              && sdk install java 17.0.2.8.1-amzn"