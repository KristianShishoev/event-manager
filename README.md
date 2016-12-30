# Event manager

A JavaEE website, that makes easier organizing and booking different kinds of events.

# Running application

The following instructions are for running application on Windows, Wildfly application server and MySQL database:

1. Download WildFly 10 (http://wildfly.org/downloads/) and extract it somewhere.

2. Download and install My SQL Server (http://dev.mysql.com/downloads/mysql/)

3. Download the MySQL connector jar (https://dev.mysql.com/downloads/connector/j/). You are going to use it later when you create a JDBC data source in WildFly.

4. Run MySQL and create user and database. Example user: root pass: admin  database: eventmanager

5. Create managment user for WildFly server (https://www.youtube.com/watch?v=8HUFaL--SwI)

6. Run Wildfly server WildFly/bin/standalone.bat

7. Follow this youtube video (https://www.youtube.com/watch?v=xSHXMcRsF0A) to setup datasource. Note that jndi name MUST be java:/mysqlDS .

8. mvn clean install will build and deploy application automatic.

9. Open the web app at http://localhost:8080/event-manager
