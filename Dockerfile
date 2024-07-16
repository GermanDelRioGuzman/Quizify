# syntax=docker/dockerfile:1
# base image
FROM node:14.17.0-alpine3.13
# install dependencies
WORKDIR /code
# copy the content of the local src directory to the working directory
ENV FLASK_APP=app.py
ENV OPENAI_API_KEY="sk-proj-LcuTwESc2d0PPONWSLnUT3BlbkFJTSdWFrmnXcD3l2iNenDG"
# set environment variables
ENV FLASK_RUN_HOST=0.0.0.0
# set environment variables
RUN apk add --no-cache gcc musl-dev linux-headers
#3. Install dependencies
COPY requirements.txt requirements.txt
# copy the requirements file to the workdir
RUN pip install -r requirements.txt
# install dependencies
EXPOSE 5000
# expose the port 5000
COPY . .
# copy the content of the local src directory to the working directory
CMD ["node", "server.js", "&", "node", "index.js"] 
# command to run on container start