FROM --platform=linux/amd64 fedora as builder

RUN yum install rpm-build -y

COPY . /repo
WORKDIR /repo
RUN ./autogen.sh sysdeps --install
RUN tito build --rpm --test
RUN ./autogen.sh
RUN ./configure --prefix=/install
RUN make -j8
RUN make install

FROM fedora as package
RUN yum install satyr libreport -y
COPY --from=builder /install /install
