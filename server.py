import socket
import signal
import sys
import random

# Read a command line argument for the port where the server
# must run.
port = 8080
if len(sys.argv) > 1:
    port = int(sys.argv[1])
else:
    print("Using default port 8080")

# Start a listening server socket on the port
sock = socket.socket()
sock.bind(('', port))
sock.listen(2)

### Contents of pages we will serve.
# Login form
login_form = """
   <form action = "http://localhost:%d" method = "post">
   Name: <input type = "text" name = "username">  <br/>
   Password: <input type = "text" name = "password" /> <br/>
   <input type = "submit" value = "Submit" />
   </form>
""" % port
# Default: Login page.
login_page = "<h1>Please login</h1>" + login_form
# Error page for bad credentials
bad_creds_page = "<h1>Bad user/pass! Try again</h1>" + login_form
# Successful logout
logout_page = "<h1>Logged out successfully</h1>" + login_form
# A part of the page that will be displayed after successful
# login or the presentation of a valid cookie
success_page = """
   <h1>Welcome!</h1>
   <form action="http://localhost:%d" method = "post">
   <input type = "hidden" name = "action" value = "logout" />
   <input type = "submit" value = "Click here to logout" />
   </form>
   <br/><br/>
   <h1>Your secret data is here:</h1>
""" % port

#### Helper functions
# Printing.
def print_value(tag, value):
    print "Here is the", tag
    print "\"\"\""
    print value
    print "\"\"\""
    print

# Signal handler for graceful exit
def sigint_handler(sig, frame):
    print('Finishing up by closing listening socket...')
    sock.close()
    sys.exit(0)
# Register the signal handler
signal.signal(signal.SIGINT, sigint_handler)


# TODO: put your application logic here!
# Read login credentials for all the users
login_file = open('passwords.txt','r')
lines = login_file.readlines()
login_file.close()
login_info = {}
for line in lines:
    v = line.strip().split()[1]
    k = line.strip().split()[0]
    login_info[k] = v.strip()

# Read secret data of all the users
secrets_file = open('secrets.txt','r')
lines = secrets_file.readlines()
secrets_file.close()
secrets_info = {}
for line in lines:
    v = line.strip().split()[1]
    k = line.strip().split()[0]
    secrets_info[k] = v.strip()

# cookie data structure
cookies_info = {}

### Loop to accept incoming HTTP connections and respond.
while True:
    client, addr = sock.accept()
    req = client.recv(1024)

    # Let's pick the headers and entity body apart
    header_body = req.split('\r\n\r\n')
    headers = header_body[0]
    body = '' if len(header_body) == 1 else header_body[1]
    print_value('headers', headers)
    print_value('entity body', body)

    # TODO: Put your application logic here!
    # Parse headers and body and perform various actions
    input_cookie_token = ""
    header_lines = headers.split('\r\n')
    for line in header_lines:
        header_name = line.split(':')[0]
        if header_name == "Cookie":
            input_cookie_token = line.split(':')[1].split('=')[1].strip()

    username = ""
    password = ""
    action = ""
    if len(header_body) > 1:
        input_list = body.split('&')
        for input in input_list:
            if input.split('=')[0] == "username":
                username = input.split('=')[1]
            if input.split('=')[0] == "password":
                password = input.split('=')[1]
            if input.split('=')[0] == "action":
                action = input.split('=')[1]
    
    html_content_to_send = ""
    headers_to_send = ""

    if (action == "logout"):
        headers_to_send = 'Set-Cookie: token=; expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n'
        html_content_to_send = logout_page
    else:
        try:
            bad_cookie = False
            good_cookie = False
            if input_cookie_token != "":
                if cookies_info.has_key(input_cookie_token):
                    cookie_user = cookies_info[input_cookie_token]
                    html_content_to_send = success_page + secrets_info[cookie_user]
                    good_cookie = True
                else:
                    bad_cookie = True
            if not good_cookie:
                if bad_cookie:
                    html_content_to_send = bad_creds_page
                elif username != "" and password == login_info[username]:
                    rand_val = random.getrandbits(64)
                    headers_to_send = 'Set-Cookie: token=' + str(rand_val) + '\r\n'
                    html_content_to_send = success_page + secrets_info[username]
                    cookies_info[str(rand_val)] = username
                elif (username != "" and password != login_info[username])\
                 or (username == "" and password != "")\
                 or (username != "" and password == ""):
                    html_content_to_send = bad_creds_page
                else:
                    html_content_to_send = login_page
        except KeyError as err:
            html_content_to_send = bad_creds_page

    # You need to set the variables:
    # (1) `html_content_to_send` => add the HTML content you'd
    # like to send to the client.
    # Right now, we just send the default login page.
    #html_content_to_send = login_page
    # But other possibilities exist, including
    # html_content_to_send = success_page + <secret>
    # html_content_to_send = bad_creds_page
    # html_content_to_send = logout_page
    
    # (2) `headers_to_send` => add any additional headers
    # you'd like to send the client?
    # Right now, we don't send any extra headers.
    #headers_to_send = ''

    # Construct and send the final response
    response  = 'HTTP/1.1 200 OK\r\n'
    response += headers_to_send
    response += 'Content-Type: text/html\r\n\r\n'
    response += html_content_to_send
    print_value('response', response)    
    client.send(response)
    client.close()
    
    print "Served one request/connection!"
    print

# We will never actually get here.
# Close the listening socket
sock.close()
