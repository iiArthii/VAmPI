import requests
import jsonschema
from flask import request, jsonify, Response
from api_views.json_schemas import ssrf_test_schema
from api_views.users import token_validator, error_message_helper

def ssrf_test():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'status': 'fail', 'message': 'Authorization header is missing.'}), 401

    token = auth_header.split(" ")[1] if " " in auth_header else auth_header
    resp = token_validator(token)
    if "error" in resp:
        return jsonify({'status': 'fail', 'message': resp["error"]}), 401

    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, ssrf_test_schema)
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype="application/json")

    external_url = request_data.get('url')
    if not external_url:
        return jsonify({'status': 'fail', 'message': 'URL parameter is required.'}), 400

    try:
        response = requests.get(external_url)
        external_content = response.text
        status_code = response.status_code
    except requests.RequestException as e:
        external_content = f"Failed to fetch content: {str(e)}"
        status_code = 500

    return jsonify({
        'status': 'success',
        'content': external_content,
        'status_code': status_code
    }), 200
