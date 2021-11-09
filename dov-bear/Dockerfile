FROM node:16

ARG APP_DIR=/app

### building 
# creates the directory and cd into it
WORKDIR ${APP_DIR}

# copy the files from local machine into the container
ADD main.js .
ADD package.json .
ADD package-lock.json .
ADD public public
ADD views views

# install packages from package.json
# node_modules will be created
RUN npm ci

### run the application
ENV PORT=3000

## Healthcheck 
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
        CMD curl -s localhost:$(PORT)/healthz || exit 1

## what are the ports used by this application
EXPOSE ${PORT}

## how to run the application
ENTRYPOINT [ "node", "main.js" ]