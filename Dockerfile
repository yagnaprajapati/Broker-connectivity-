# Use OpenJDK base image
FROM openjdk:17

# Set the working directory
WORKDIR /app

# Copy source code
COPY src/ ./src/

# Compile the Java source code
RUN javac src/*.java

# Run the main class
CMD ["java", "-cp", "src", "Main"]
