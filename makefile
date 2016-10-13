


jar:
	#javac -d build src/com/camelinc/burp/*.java
	javac -Xlint:unchecked -classpath ./src -d build src/burp/*.java
	jar cmf MANIFEST.MF bin/burpextender.jar -C build .
