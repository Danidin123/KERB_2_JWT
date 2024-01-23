FROM ubuntu
COPY f5/ /f5
RUN apt-get update -y && \
    apt-get install -y pip python3 && \
    pip3 install flask f5-sdk
WORKDIR /f5
CMD python3 main.py

