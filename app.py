import adal
import flask
import uuid
import requests
import config

from flask import jsonify


app = flask.Flask(__name__)
app.debug = True
app.secret_key = 'development'

PORT = 5000  # A flask app by default runs on PORT 5000
AUTHORITY_URL = config.AUTHORITY_HOST_URL + '/' + config.TENANT
REDIRECT_URI = 'http://localhost:{}/getAToken'.format(PORT)
TEMPLATE_AUTHZ_URL = ('https://login.microsoftonline.com/{}/oauth2/authorize?' +
                      'response_type=code&client_id={}&redirect_uri={}&' +
                      'state={}&resource={}')


@app.route("/")
def main():
    login_url = 'http://localhost:{}/login'.format(PORT)
    resp = flask.Response(status=307)
    resp.headers['location'] = login_url
    return resp


@app.route("/login")
def login():
    auth_state = str(uuid.uuid4())
    flask.session['state'] = auth_state
    authorization_url = TEMPLATE_AUTHZ_URL.format(
        config.TENANT,
        config.CLIENT_ID,
        REDIRECT_URI,
        auth_state,
        config.RESOURCE)
    resp = flask.Response(status=307)
    resp.headers['location'] = authorization_url
    return resp


@app.route("/getAToken")
def main_logic():
    code = flask.request.args['code']
    state = flask.request.args['state']
    if state != flask.session['state']:
        raise ValueError("State does not match")
    auth_context = adal.AuthenticationContext(AUTHORITY_URL)
    token_response = auth_context.acquire_token_with_authorization_code(code, REDIRECT_URI, config.RESOURCE, config.CLIENT_ID, config.CLIENT_SECRET)
    # It is recommended to save this to a database when using a production app.
    flask.session['access_token'] = token_response['accessToken']
    return flask.redirect('/graphcall')

'''
@app.route('/graphcall')
def graphcall():
    if 'access_token' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    endpoint = config.RESOURCE + '/' + config.API_VERSION + '/me/'
    http_headers = {'Authorization': 'Bearer ' + flask.session.get('access_token'),
                    'User-Agent': 'adal-python-sample',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'client-request-id': str(uuid.uuid4())}
    graph_data = requests.get(endpoint, headers=http_headers, stream=False).json()
    return flask.render_template('display_graph_info.html', graph_data=graph_data)
'''

@app.route('/graphcall')
def graphcall():
    if 'access_token' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    
    print ('Bearer ' + flask.session.get('access_token'))
    
    http_headers = {'Authorization': 'Bearer ' + flask.session.get('access_token'),
                    'User-Agent': 'adal-python-sample',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'client-request-id': str(uuid.uuid4())}


    # build lookup table for privileged roles
    # get roles
    #priv_roles = config.RESOURCE + '/' + config.API_VERSION + "/privilegedRoles?$filter=startswith(name,'Glob')"
    priv_roles = config.RESOURCE + '/' + config.API_VERSION + '/privilegedRoles'
    
    graph_data_priv_roles = requests.get(priv_roles, headers=http_headers, stream=False).json()

    for role in graph_data_priv_roles['value']:
        print(".. processing : " + role["name"])
        role.update( {'role_members' : []} )

        # get priv role members
        priv_role_members = config.RESOURCE + '/' + config.API_VERSION + '/privilegedRoles/' + role["id"] + '/assignments'
        graph_data_priv_role_members = requests.get(priv_role_members, headers=http_headers, stream=False).json()

        for priv_user in graph_data_priv_role_members['value']:
            this_user = get_aad_user(priv_user["userId"], http_headers)

            role["role_members"].append(
                {
                    "displayName": this_user["displayName"],
                    "userPrincipalName": this_user["userPrincipalName"],
                    "accountEnabled": this_user["accountEnabled"],
                    "employeeId": this_user["employeeId"],
                    "id": this_user["id"],
                    "jobTitle": this_user["jobTitle"],
                    "department": this_user["department"],
                    "onPremisesSyncEnabled": this_user["onPremisesSyncEnabled"]
                })
 
    return jsonify(graph_data_priv_roles)

    #return flask.render_template('display_nested_graph_info.html', graph_data_priv_roles=graph_data_priv_roles)
    #return jsonify(graph_data_priv_roles)


    #endpoint = config.RESOURCE + '/' + config.API_VERSION + '/me/'
    #graph_data = requests.get(endpoint, headers=http_headers, stream=False).json()
    #return graph_data
    #return flask.render_template('display_graph_info.html', graph_data=graph_data)


def get_aad_user(userId, http_headers):
    if 'access_token' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    
    print('   --> aad user lookup: ' + userId)
    endpoint_aad_user = config.RESOURCE + '/' + config.API_VERSION + '/users/' + userId
    graph_data_aad_user = requests.get(endpoint_aad_user, headers=http_headers, stream=False).json()

    return graph_data_aad_user


'''
@app.route('/graphcall')
def graphcall():
    if 'access_token' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    #endpoint = config.RESOURCE + '/' + 'beta' + '/privilegedRoles/'
    endpoint = config.RESOURCE + '/' + config.API_VERSION + '/me/'
    http_headers = {'Authorization': 'Bearer ' + flask.session.get('access_token'),
                    'User-Agent': 'adal-python-sample',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'client-request-id': str(uuid.uuid4())}
    graph_data = requests.get(endpoint, headers=http_headers, stream=False).json()
    print (graph_data)
    #return flask.render_template('display_graph_info.html', graph_data=graph_data)
'''

#def ()

if __name__ == "__main__":
    app.run()