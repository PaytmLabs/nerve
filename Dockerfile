FROM centos:7

ARG TARGET_FOLDER=/opt/nerve

RUN yum install epel-release -y && \
    yum update -y && \
    yum install -y gcc && \
    yum install -y redis && \
    yum install -y python3 && \
    yum install -y python3-pip && \
    yum install -y python3-devel && \
    yum install -y wget && \
    yum install -y bzip2 && \
    yum install -y make && \
    yum install -y gcc-c++ && \
    yum install -y postgresql-devel && \
    yum install -y libffi-devel && \
    yum install -y openssl-devel && \
    yum install -y libjpeg-turbo-devel && \
    yum install -y openssh-clients && \
    yum clean all


RUN wget https://nmap.org/dist/nmap-7.92.tar.bz2
RUN bzip2 -cd nmap-7.92.tar.bz2 | tar xvf -
RUN cd nmap-7.92 && ./configure && make && make install

RUN mkdir /opt/nerve

ADD bin $TARGET_FOLDER/bin
ADD core $TARGET_FOLDER/core
ADD db $TARGET_FOLDER/db
ADD install $TARGET_FOLDER/install
ADD logs $TARGET_FOLDER/logs
ADD reports $TARGET_FOLDER/reports
ADD rules $TARGET_FOLDER/rules
ADD static $TARGET_FOLDER/static
ADD templates $TARGET_FOLDER/templates
ADD views $TARGET_FOLDER/views
ADD views_api $TARGET_FOLDER/views_api

COPY config.py $TARGET_FOLDER
COPY main.py $TARGET_FOLDER
COPY requirements.txt $TARGET_FOLDER
COPY start.sh $TARGET_FOLDER
COPY version.py $TARGET_FOLDER
WORKDIR $TARGET_FOLDER/

RUN pip3 install --user -r requirements.txt
RUN chmod 755 main.py
RUN chmod 755 start.sh
ENTRYPOINT ["/opt/nerve/start.sh"]

EXPOSE 8080/tcp

