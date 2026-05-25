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
RUN dnf install clang -y
RUN clang++ /repo/mayhem/fuzz_abrt_koops_extract_version.cpp -fsanitize=fuzzer,address -I /install/include/abrt/ -I /usr/include/glib-2.0/ -I /usr/lib64/glib-2.0/include/ -L /install/lib/ -labrt -o /fuzz
FROM fedora as package
RUN yum install satyr libreport -y
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_abrt_koops_extract_version
ENV LD_LIBRARY_PATH=/install/lib/
