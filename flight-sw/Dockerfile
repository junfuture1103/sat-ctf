FROM gcc:13-bookworm
WORKDIR /app
COPY flight_sw.c entrypoint.sh ./
# Fair ret2win: no stack canary, no PIE (fixed code addresses), symbols kept.
RUN gcc -O0 -fno-stack-protector -no-pie -w flight_sw.c -o flight_sw \
    && chmod +x entrypoint.sh
EXPOSE 9020
ENTRYPOINT ["./entrypoint.sh"]
