FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /workspace
COPY pom.xml ./
COPY rasp-core/pom.xml rasp-core/pom.xml
COPY rasp-spring-boot-autoconfigure/pom.xml rasp-spring-boot-autoconfigure/pom.xml
COPY rasp-spring-boot-starter/pom.xml rasp-spring-boot-starter/pom.xml
COPY rasp-samples/pom.xml rasp-samples/pom.xml
COPY rasp-core/src rasp-core/src
COPY rasp-spring-boot-autoconfigure/src rasp-spring-boot-autoconfigure/src
COPY rasp-samples/src rasp-samples/src
RUN mvn --batch-mode --no-transfer-progress clean verify

FROM eclipse-temurin:25-jre
WORKDIR /app
COPY --from=build --chown=10001:10001 /workspace/rasp-samples/target/rasp-samples-1.0.0-SNAPSHOT.jar app.jar
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-Djava.io.tmpdir=/tmp", "-jar", "/app/app.jar"]
