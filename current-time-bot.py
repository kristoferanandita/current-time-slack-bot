import os
import time
import datetime
import hmac
import hashlib
from flask import abort, Flask, jsonify, request

app = Flask(__name__)

def is_request_valid(request):
    """
    Verify the request signature of the request sent from Slack.
    Verification is done by comparing the Slack signature in the request
    header to the newly generated hash using the app's signing secret
    and request data.
    """
    
    slack_signing_secret = os.environ.get('SLACK_SIGNING_SECRET')
    request_body = request.get_data()
    timestamp = request.headers.get('X-Slack-Request-Timestamp')

    # Replay attack prevention is still WIP
    #if abs(time.time() - int(timestamp)) > 60 * 5:
    #    return False
    
    sig_basestring = str.encode('v0:' + str(timestamp) + ':') + request_body
    my_signature = 'v0=' + hmac.new(
        str.encode(slack_signing_secret),
        sig_basestring,
        hashlib.sha256
    ).hexdigest()
    slack_signature = request.headers['X-Slack-Signature']
    if hmac.compare_digest(my_signature, slack_signature):
        return True

@app.route('/time', methods=['POST'])
def time():
    """
    App endpoint used in request URL of /time command.
    """
    if not is_request_valid(request):
        abort(400)

    current_time = datetime.datetime.now().strftime('%H:%M')
    return jsonify(
        response_type='in_channel',
        text='The current time is ' + current_time,
    )


