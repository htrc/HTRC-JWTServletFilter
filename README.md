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
`libraryDependencies += "edu.indiana.d2i.htrc" %% "jwt-servletfilter" % "1.2"`

## Maven
```
<dependency>
    <groupId>edu.indiana.d2i.htrc</groupId>
    <artifactId>jwt-servletfilter</artifactId>
    <version>1.2</version>
</dependency>
```

## Gradle

`compile 'edu.indiana.d2i.htrc:jwt-servletfilter:1.2'`

## JWTServletFilter Configuration

```JWTServletFilter``` can be configured via ```web.xml``` as shown below.

```xml
<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="2.5">
    <servlet>
        <servlet-name>securedAPI</servlet-name>
        <servlet-class>edu.indiana.d2i.htrc.SecuredAPI</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>securedAPI</servlet-name>
        <url-pattern>/*</url-pattern>
    </servlet-mapping>
    <filter>
        <filter-name>jwtFilter</filter-name>
        <filter-class>edu.indiana.d2i.htrc.security.JWTServletFilter</filter-class>
        <init-param>
            <param-name>htrc.jwtfilter.config</param-name>
            <param-value>filter-config-path</param-value>
        </init-param>
    </filter>

    <filter-mapping>
        <filter-name>jwtFilter</filter-name>
        <servlet-name>securedAPI</servlet-name>
    </filter-mapping>
</web-app>
```

```JWTServletFilter``` configuration can be specified via HOCON configuration file that looks like below.

```hocon
jwtfilter {
  jwt {
    token {
      issuer {
        // Mandatory configuration and used for issuer validation
        id = "https://devenv-notls-is:443/oauth2/token"
        // Optional configuration and used only when JWT token is signed using a X509 key
        public-key { 
          keystore = ""
          keystore-password = ""
          publickey-alias = ""
        }
        // Optional configuration and used when JWT filter is signed using a simple shared secret
        secret = ""
      }
      verification {
        algorithm = "RSASHA256"
      }
    }
  }
  // Optional. Use only if you need to define custom header mappings.
  claim-mappings {
    email = "htrc-email"
    sub = "htrc-user"
    iss = "htrc-token-issuer"
  }
}
```

## TokenVerifier Configuration

```edu.indiana.d2i.htrc.security.jwt.TokenVerifier``` can be used in your web apps to validate and decode JWT tokens as shown below.

```java
TokenVerifier tokenVerifier = new TokenVerifier(tokenVerifierConfig);
JWT token = tokenVerifier.verify(jwtToken);
```

HOCON based configuration is supported via ```edu.indiana.d2i.htrc.security.jwt.HOCONTokenVerifierConfiguration```. HOCON token verifier configuration is shown below.

```hocon
token {
  issuer {
    // Mandatory configuration and used for issuer validation
    id = "https://devenv-notls-is:443/oauth2/token"
    // Optional configuration and used only when JWT token is signed using a X509 key
    public-key { 
      keystore = ""
      keystore-password = ""
      publickey-alias = ""
    }
    // Optional configuration and used when JWT filter is signed using a simple shared secret
    secret = ""
  }
  verification {
    algorithm = "RSASHA256"
  }
}
```
