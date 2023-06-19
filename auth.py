from burp import IBurpExtender
from burp import IHttpListener
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import ITab
from java.awt import BorderLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JButton
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JTextField
from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
import threading
from javax.swing import SwingWorker
from javax.swing import JFrame
from java.awt import EventQueue
import random,hmac,base64,time,string,json,hashlib
class CustomHeadersWorker(SwingWorker):
    def __init__(self, callbacks, http_service, updated_request_obj):
        self.callbacks = callbacks
        self.http_service = http_service
        self.updated_request_obj = updated_request_obj

    def doInBackground(self):
        self.callbacks.makeHttpRequest(self.http_service, self.updated_request_obj)

    def done(self):
        pass


class CustomHeadersActionListener(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
     #   self.extender.frame.setVisible(True)
        self.extender.new_headers = self.extender.generate_headers(self)
        self.extender.openCustomHeaders(self.invocation)


class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Custom Headers")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        # Initialize options with default values
        self.__base_rapid_api_key = "https://api.not_used_you_can_ignore.com/"
        self.__access_key = "enter_acess"
        self.__secret_key = "enter_Secret"

        # Create UI components for options
        self.base_url_label = JLabel("Base URL:")
        self.base_url_field = JTextField(30)
        self.base_url_field.setText(self.__base_rapid_api_key)

        self.access_key_label = JLabel("Access Key:")
        self.access_key_field = JTextField(30)
        self.access_key_field.setText(self.__access_key)

        self.secret_key_label = JLabel("Secret Key:")
        self.secret_key_field = JTextField(30)
        self.secret_key_field.setText(self.__secret_key)

        self.save_button = JButton("Save", actionPerformed=self.save_options)

        # Add the UI components to a panel
        self.panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.gridx = 0
        constraints.gridy = GridBagConstraints.RELATIVE
        constraints.anchor = GridBagConstraints.WEST
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets.left = 5
        constraints.insets.right = 5
        constraints.insets.top = 5
        constraints.insets.bottom = 5
        self.panel.add(self.base_url_label, constraints)
        self.panel.add(self.base_url_field, constraints)
        self.panel.add(self.access_key_label, constraints)
        self.panel.add(self.access_key_field, constraints)
        self.panel.add(self.secret_key_label, constraints)
        self.panel.add(self.secret_key_field, constraints)
        self.panel.add(self.save_button, constraints)
        self.frame = JFrame("RapydAuth Custom Headers Extension")
        self.frame.setSize(400, 300)
        self.frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)

        # Add the panel with UI components to the frame
        self.frame.getContentPane().add(self.panel, BorderLayout.CENTER)
        self.new_headers = None
        self.invoc = None
        self.headers = {}
        # Show the frame
        


    def createMenuItems(self, invocation):
            menu_list = []
            self.invoc = invocation
            if invocation.getToolFlag() == self._callbacks.TOOL_REPEATER:
                menu_item = JMenuItem("RapydAuth")
                menu_item.addActionListener(CustomHeadersActionListener(self, invocation))
                menu_list.append(menu_item)
            return menu_list

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            pass
        if not messageIsRequest and toolFlag == self._callbacks.TOOL_REPEATER:
            response = messageInfo.getResponse()
            print(self._helpers.bytesToString(response))  

    # ...
    def get_current_headers(self, headers_str):
        x = headers_str[1:]
        x = x[:-1]
        x = x.split(',')
        for i in x:
            if ':' not in i:
                x.remove(i)
        y = {}
        for i in x:
            k,v = i.split(':')
            y[k.lstrip()] =v +'\r\n'
        our_intresting_headers = ["Access_key", "Idempotency","Timestamp", "Salt","Signature"]
        to_ret = {}
        for header in our_intresting_headers:
            if header in y.keys():
                to_ret[header] = y[header]
        return to_ret


    def openCustomHeaders(self, invocation):
        headers = self.headers
        http_request = invocation.getSelectedMessages()[0].getRequest()
        http_service = invocation.getSelectedMessages()[0].getHttpService()
        request_info = self._helpers.analyzeRequest(http_service, http_request)
        request = invocation.getSelectedMessages()[0].getRequest()
        existing_headers = self._helpers.analyzeRequest(http_service, http_request).getHeaders()
        if len(self.__access_key) < 2:
            return
        self.__access_key = str(self.__access_key)
        re = request_info
        method =re.getMethod().decode()
        path = re.getUrl().getPath()
        if re.getUrl().getQuery():
            path = re.getUrl().getPath() + '?'+re.getUrl().getQuery()
        salt = self.generate_salt()
        timestamp = str(self.get_unix_time())
        body_offset = request_info.getBodyOffset()
        body = http_request[body_offset:]
        if len(body)< 3:
            body = ''
        method,path = str(method),str(path)
        try:
            str_body = json.dumps(body, separators=(',', ':'), ensure_ascii=False) if len(body) > 2 else ''
        except TypeError:
            str_body = ''
        salt, timestamp, signature = self.generate_signature(http_method=method, path=path, body=str_body)
        headers = self.prepare_headers(salt,timestamp,signature)
        headers['Content-Type'] = 'application/json'
        headers['idempotency'] = str(self.get_unix_time()) + salt
        # Append custom headers to the request
     
       # print(headers)
        already_existing = self.get_current_headers(str(existing_headers))
        headers_str = "\r\n".join(key + ": " + value for key, value in headers.items())
        headers_bytes = self._helpers.stringToBytes(headers_str)
        # Send the modified request using the makeHttpRequest method
        headers_real = request[:request_info.getBodyOffset()-2]
        headers_as_string = self._helpers.bytesToString(headers_real)
        our_intresting_headers = ["Access_key", "Idempotency","Timestamp", "Salt","Signature"]
        for intresting_header in our_intresting_headers:
            if already_existing:
              #  print(headers)
                headers_as_string = headers_as_string.replace(already_existing[intresting_header],' '+headers[intresting_header.lower()]+'\r\n')
                updated_headers = self._helpers.stringToBytes(headers_as_string)
                updated_request =updated_headers
                updated_request.extend(request[request_info.getBodyOffset():])
            else:
                    
                updated_request = bytearray(headers_real)
                updated_request.extend(headers_bytes)
            # updated_request.extend(b"\r\n\r\n")  # Add an empty line as a separator
                updated_request.extend(request[request_info.getBodyOffset():])

        # Update the request with the custom headers
        if invocation.getToolFlag() != self._callbacks.TOOL_REPEATER:
            # Send the modified request to the Repeater tool
            self._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), http_service.getProtocol() == "https", updated_request, None)
        else:
            # Update the request in the Repeater tool
            invocation.getSelectedMessages()[0].setRequest(updated_request)
           # worker = CustomHeadersWorker(self._callbacks, http_service, updated_request)
           # worker.execute()




    def generate_salt(self):
        return ''.join(random.sample(string.ascii_letters + string.digits, 12))

    def get_unix_time(self):
        return int(time.time())

    def generate_signature(self, http_method, path, body):
        salt = self.generate_salt()
        timestamp = str(self.get_unix_time())
        to_sign = (http_method.lower(), path, salt, str(timestamp), str(self.__access_key), str(self.__secret_key), body)
        print(body, type(body))
        h = hmac.new(self.__secret_key.encode('utf-8'), ''.join(to_sign).encode('utf-8'), hashlib.sha256)
        signature = str(base64.urlsafe_b64encode(str.encode(h.hexdigest())).decode())
        return salt, timestamp, signature

    def prepare_headers(self, salt, timestamp, signature):
        headers = {"salt": salt, "access_key": self.__access_key, "timestamp": timestamp,
                   "signature": str(signature.decode())}
        return headers

    def generate_headers(self,*args):
        # Retrieve values from UI components or use default values
        if bool(self.__access_key) and bool(self.__secret_key):
             self.headers = {
            "Base-URL": "",
            "Access-Key": self.__access_key,
            "Secret-Key": self.__secret_key
        }
             return
        self.frame.setVisible(True)
        base_url = self.base_url_field.getText() if self.base_url_field.getText() else self.__base_rapid_api_key
        access_key = self.access_key_field.getText() if self.access_key_field.getText() else self.__access_key
        secret_key = self.secret_key_field.getText() if self.secret_key_field.getText() else self.__secret_key
        
        # Generate custom headers based on the input values
        self.headers = {
            "Base-URL": base_url,
            "Access-Key": access_key,
            "Secret-Key": secret_key
        }
    def save_options(self, event):
        self.__base_rapid_api_key = self.base_url_field.getText()
        self.__access_key = self.access_key_field.getText()
        self.__secret_key = self.secret_key_field.getText()
        self.headers = {
            "Base-URL": self.__base_rapid_api_key,
            "Access-Key": self.__access_key,
            "Secret-Key": self.__secret_key
        }
        self.openCustomHeaders(self.invoc)
        self.frame.setVisible(False)
        self.frame.dispose()
        
       
        


    def makeRequest(self, http_service, updated_request_obj):
        self._callbacks.makeHttpRequest(http_service, updated_request_obj)
    # Other methods and event handlers...
