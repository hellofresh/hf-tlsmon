# See: https://github.com/gliderlabs/docker-alpine
FROM gliderlabs/alpine:3.4

#
# Usage:
# - mount 'sslcheck' hosts file to '/etc/hf-tlsmon/tlshosts_to_check',
# - use '-e' to set following environment variables: 
#   SLACK_INCOMING_WEBHOOK_URL -- full URL as provided by Slack,
#   CERT_ALERT_THRESHOLD       -- an integer value indicating when an alert gets raised
#                                 for a TLS host based on the days left until a TLS cert expires,
#   STATSD_ADDRESS             -- optinal: to publish a hearbeat counter metric 'tlsmon.alive'
#                                 to a StatsD instance; format must be 'host:port'.
# - use '-it' and '--rm' run options (use only '-i' in a cron environment).
#

# The release version of hf-tlsmon to add to the container.
ENV HF_TLSMON_REL v0.0.8

# Put sslcheck command into place.
COPY sslcheck /usr/local/bin/sslcheck

# Put hf-tlsmon utility into place. Use GitHub release version.
ADD https://github.com/hellofresh/hf-tlsmon/releases/download/$HF_TLSMON_REL/hf-tlsmon /usr/local/bin/hf-tlsmon

# Make sure hf-tlsmon is executable.
RUN chmod +x /usr/local/bin/hf-tlsmon

# Add SSL root cert where Go(lang) expects it.
ADD ca-certificates.crt /etc/ssl/certs/

# Allow mounting of sslcheck hosts file into container as '/etc/hf-tlsmon/tlshosts_to_check'.
VOLUME ["/etc/hf-tlsmon"]

# It is a cmd-like container, so hf-tlsmon utility runs immediately after container startup.
ENTRYPOINT ["/usr/local/bin/hf-tlsmon"]
