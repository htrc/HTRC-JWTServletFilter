# HTRC-JWT-ServletFilter
Servlet filter for validating HTTP requests with JWT tokens

# Build

To generate a package that can be referenced from other projects:

```
$ ./gradlew build
```

then find the result in ```build/libs/```

# Usage

## SBT
`libraryDependencies += "edu.indiana.d2i.htrc" %% "jwt-servletfilter" % "0.1-SNAPSHOT"`

## Maven
```
<dependency>
    <groupId>edu.indiana.d2i.htrc</groupId>
    <artifactId>jwt-servletfilter</artifactId>
    <version>0.1-SNAPSHOT</version>
</dependency>
```

## Gradle

`compile 'edu.indiana.d2i.htrc:jwt-servletfilter:0.1-SNAPSHOT'`


