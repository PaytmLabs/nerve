import time

from core.security import session_required
from flask import Blueprint, Response, stream_with_context

stream = Blueprint('stream', __name__,
                    template_folder='templates')

@stream.route('/log')
@session_required
def view_stream():
  def generate():
    with open('logs/nerve.log') as f:
      while True:
        yield f.read()
        time.sleep(1)
  return Response(stream_with_context(generate()), mimetype='text/plain')
