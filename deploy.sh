#!/bin/bash

# deployment script

# declare variables
TOMCAT_DIR=apache-tomcat-11.0.0
APP_DIR=app_B
WAR_FILE=postservlet-0.0.1-SNAPSHOT.war
TARGET_WAR=postservlet.war
WORK_DIR=~/WORK/CODE/PRACTICE/poc_debr_POST_iframe

# use the working directory
cd $WORK_DIR

# build app, app is in app_B folder
echo "Building app..."
mvn clean install -f $APP_DIR/pom.xml

# stop tomcat
echo "Stopping Tomcat..."
sh ./$TOMCAT_DIR/bin/shutdown.sh

# remove old app
echo "Removing old app..."
rm -rf ./$TOMCAT_DIR/webapps/$TARGET_WAR*

# copy new app
echo "Copying new app..."
cp ./$APP_DIR/target/$WAR_FILE ./$TOMCAT_DIR/webapps/$TARGET_WAR

# start tomcat
echo "Starting Tomcat..."
export JPDA_OPTS="-agentlib:jdwp=transport=dt_socket,address=8000,server=y,suspend=n"
sh ./$TOMCAT_DIR/bin/catalina.sh jpda start

# Keep the script running to keep Tomcat up
echo "Tomcat is running. Press [CTRL+C] to stop."
while true; do
  sleep 60
done
