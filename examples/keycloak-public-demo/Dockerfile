FROM eclipse-temurin:21-jre
COPY --chown=1000:1000 keycloak /opt/keycloak
USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
