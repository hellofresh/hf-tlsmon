hf-tlsmon monitors TLS/SSL hosts 
=========


It's a cmd-like Docker image that uses the really nice [sslcheck](https://github.com/rossdylan/sslcheck) tool to actually check the validity of TLS certificates.  
Therefore the argument for `sslcheck`'s `-file` argument has to be mounted _inside_ the container to the exact location of `/etc/hf-tlsmon/tlshosts_to_check`.  
If the TLS certificate is less or equal valid for `CERT_ALERT_THRESHOLD` remaining days, an alert will be posted into a Slack channel using the cool library [slack-incoming-webhooks](https://github.com/monochromegane/slack-incoming-webhooks). The Slack incoming webhook URL must be provided as environment variable `SLACK_INCOMING_WEBHOOK_URL`.

Usage example:

      docker run \
      -it \
      -e SLACK_INCOMING_WEBHOOK_URL="<your-secret-incoming-webhook-URL>" \
      -e CERT_ALERT_THRESHOLD="<num-of-remaining-days-to-trigger-altert>" \
      -e STATSD_ADDRESS="<your-statsd-host>:<your-statsd-port>" \
	  -e TEXT_MSG_SPECIAL_WORD=<your-special-word-here> \
      --rm \
      -v <your-sslcheck-hosts-file>:/etc/hf-tlsmon/tlshosts_to_check \
      quay.io/hellofresh/hf-tlsmon:<GitHub-releases-version>

The [StatsD](https://github.com/etsy/statsd) address provided via `STATSD_ADDRESS` is optional. Without it, `hf-tlsmon` will still work but not publish it's aliveness metric.  
The other _optional_ environment variable is `TEXT_MSG_SPECIAL_WORD` as defined in [Slack Basic message formatting - Variables](https://api.slack.com/docs/message-formatting#variables). If not provided, it defaults to `<!group>`.

License
-------

    Copyright (C) 2016 HelloFresh SE

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
