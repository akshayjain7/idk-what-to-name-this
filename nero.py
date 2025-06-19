# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController, IContextMenuFactory
from javax.swing import JPanel, JLabel, JToggleButton, JScrollPane, JTable, JSplitPane, JTabbedPane, DefaultListModel, JList, JButton, JMenuItem
from javax.swing.table import AbstractTableModel
from javax.swing.event import ListSelectionListener
from java.awt import Dimension
from threading import Lock
import datetime
from java.awt import Color
from javax.swing import JTable
from java.awt.event import ActionListener
from java.util import LinkedList
from thread import start_new_thread

class LogEntry:
    def __init__(self, method, url, header_removed, request_time, messageInfo, status):
        self.method = method
        self.url = url
        self.header_removed = header_removed
        self.request_time = request_time
        self.messageInfo = messageInfo
        self.status = status

class LogTableModel(AbstractTableModel):
    def __init__(self, log_entries):
        self.log_entries = log_entries
        self.columns = ["#", "Method", "URL", "Header Removed", "Time", "Status"]

    def getRowCount(self):
        return len(self.log_entries)

    def getColumnCount(self):
        return len(self.columns)

    def getColumnName(self, col):
        return self.columns[col]

    def getValueAt(self, row, col):
        entry = self.log_entries[row]
        if col == 0:
            return row + 1
        elif col == 1:
            return entry.method
        elif col == 2:
            return entry.url
        elif col == 3:
            return "Yes" if entry.header_removed else "No"
        elif col == 4:
            return entry.request_time
        elif col == 5:
            return entry.status
        return ""

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Header Remover Interceptor")

        self._lock = Lock()
        self.headers_to_remove = []
        self.intercept_enabled = False
        self.log_entries = []
        self.log_model = LogTableModel(self.log_entries)
        self._currentlyDisplayedItem = None

        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)

        self.initUI()
        self._callbacks.registerHttpListener(self)
        
        # Try registering context menu factory with detailed logging
        try:
            print("[DEBUG] Attempting to register context menu factory...")
            self._callbacks.registerContextMenuFactory(self)
            print("[+] Context menu factory registered successfully")
            
            # Test if our createMenuItems method exists
            if hasattr(self, 'createMenuItems'):
                print("[DEBUG] createMenuItems method exists")
            else:
                print("[!] createMenuItems method NOT found!")
                
        except Exception as e:
            print("[!] Failed to register context menu factory:", str(e))
            import traceback
            traceback.print_exc()
            
        self._callbacks.addSuiteTab(self)
        print("[+] Header Remover Interceptor Loaded")
        print("[DEBUG] Extension registration complete")

    def initUI(self):
        self.config_panel = JPanel()
        self.config_panel.setLayout(None)

        self.toggle_button = JToggleButton("Intercept Off", actionPerformed=self.toggleIntercept)
        self.toggle_button.setBounds(20, 20, 150, 30)
        self.config_panel.add(self.toggle_button)

        self.headerListModel = DefaultListModel()
        self.headerList = JList(self.headerListModel)
        scrollHeaderList = JScrollPane(self.headerList)
        scrollHeaderList.setBounds(20, 60, 300, 100)
        self.config_panel.add(scrollHeaderList)
        
        remove_button = JButton("Remove Selected Header", actionPerformed=self.removeSelectedHeader)
        remove_button.setBounds(20, 170, 200, 30)
        self.config_panel.add(remove_button)


        self.recentHeadersModel = DefaultListModel()
        self.recentHeadersList = JList(self.recentHeadersModel)
        scrollRecent = JScrollPane(self.recentHeadersList)
        scrollRecent.setBounds(340, 60, 300, 100)
        self.config_panel.add(scrollRecent)

        add_button = JButton("Add Header to Remove", actionPerformed=self.addHeader)
        add_button.setBounds(340, 170, 200, 30)
        self.config_panel.add(add_button)

        clear_logs_button = JButton("Clear Logs", actionPerformed=self.clearLogs)
        clear_logs_button.setBounds(560, 170, 120, 30)
        self.config_panel.add(clear_logs_button)

        self.tabs = JTabbedPane()
        self.tabs.addTab("Config", self.config_panel)
        self.tabs.addTab("Request", self._requestViewer.getComponent())
        self.tabs.addTab("Response", self._responseViewer.getComponent())

        self.log_table = ColoredTable(self.log_model, self)
        self.log_table.getSelectionModel().addListSelectionListener(self.onTableSelect)
        
        # Configure table properties to ensure all columns are visible
        self.log_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self.log_table.setFillsViewportHeight(True)
        
        # Set preferred column widths to ensure status column is visible
        columnModel = self.log_table.getColumnModel()
        if columnModel.getColumnCount() >= 6:
            columnModel.getColumn(0).setPreferredWidth(50)   # #
            columnModel.getColumn(1).setPreferredWidth(80)   # Method
            columnModel.getColumn(2).setPreferredWidth(300)  # URL
            columnModel.getColumn(3).setPreferredWidth(100)  # Header Removed
            columnModel.getColumn(4).setPreferredWidth(120)  # Time
            columnModel.getColumn(5).setPreferredWidth(80)   # Status
        
        scrollTable = JScrollPane(self.log_table)
        scrollTable.setPreferredSize(Dimension(800, 120))

        self.splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.splitPane.setTopComponent(scrollTable)
        self.splitPane.setBottomComponent(self.tabs)
        self.splitPane.setDividerLocation(150)

    def toggleIntercept(self, event):
        self.intercept_enabled = not self.intercept_enabled
        self.toggle_button.setText("Intercept On" if self.intercept_enabled else "Intercept Off")
        
    def removeSelectedHeader(self, event):
        selected = self.headerList.getSelectedValue()
        if selected:
            header = selected.strip().lower()
            self.headers_to_remove = [h for h in self.headers_to_remove if h.lower() != header]
            self.headerListModel.removeElement(selected)
            print("[−] Header removed from removal list:", selected)    

    def addHeader(self, event):
        selected = self.recentHeadersList.getSelectedValue()
        if selected:
            header = selected.split(":", 1)[0].strip()
            if header.lower() not in [h.lower() for h in self.headers_to_remove]:
                self.headers_to_remove.append(header)
                self.headerListModel.addElement(header)
                print("[+] Header added:", header)
            self.replayCurrentRequestWithAllRemovals()

    def replayCurrentRequestWithAllRemovals(self):
        if self._currentlyDisplayedItem is None:
            return
        try:
            request = self._currentlyDisplayedItem.getRequest()
            analyzed = self._helpers.analyzeRequest(request)
            headers = list(analyzed.getHeaders())
            body = request[analyzed.getBodyOffset():]
            to_remove = [h.lower() for h in self.headers_to_remove]
            new_headers = [h for h in headers if h.split(":", 1)[0].strip().lower() not in to_remove]
            modified_request = self._helpers.buildHttpMessage(new_headers, body)
            httpService = self._currentlyDisplayedItem.getHttpService()
            newMessageInfo = self._callbacks.makeHttpRequest(httpService, modified_request)
            analyzedNew = self._helpers.analyzeRequest(newMessageInfo)
            method = analyzedNew.getMethod()
            url = str(analyzedNew.getUrl())
            
            # Extract status from response
            status = "N/A"
            response = newMessageInfo.getResponse()
            if response:
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers_response = analyzedResponse.getHeaders()
                if headers_response and len(headers_response) > 0:
                    status_line = headers_response[0]  # First line contains status
                    if " " in status_line:
                        status = status_line.split(" ")[1]  # Extract status code
                        print("[+] Extracted status:", status, "from:", status_line)
                    else:
                        print("[!] Invalid status line format:", status_line)
                else:
                    print("[!] No response headers found")
            else:
                print("[!] No response received")
            
            req_time = datetime.datetime.now().strftime('%H:%M:%S %m/%d/%y')
            entry = LogEntry(method, url, True, req_time, newMessageInfo, status)
            self._lock.acquire()
            try:
                self.log_entries.append(entry)
                self.log_model.fireTableRowsInserted(len(self.log_entries) - 1, len(self.log_entries) - 1)
            finally:
                self._lock.release()
            self._currentlyDisplayedItem = newMessageInfo
            self._requestViewer.setMessage(newMessageInfo.getRequest(), True)
            self._responseViewer.setMessage(newMessageInfo.getResponse(), False)
        except Exception as e:
            print("[!] Error replaying request:", str(e))

    def onTableSelect(self, event):
        row = self.log_table.getSelectedRow()
        if row < 0 or row >= len(self.log_entries):
            return
        entry = self.log_entries[row]
        self._currentlyDisplayedItem = entry.messageInfo
        self._requestViewer.setMessage(entry.messageInfo.getRequest(), True)
        self._responseViewer.setMessage(entry.messageInfo.getResponse(), False)
        analyzed = self._helpers.analyzeRequest(entry.messageInfo.getRequest())
        self.recentHeadersModel.clear()
        for h in analyzed.getHeaders():
            self.recentHeadersModel.addElement(h)

    def getTabCaption(self):
        return "Header Remover"

    def getUiComponent(self):
        return self.splitPane

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService() if self._currentlyDisplayedItem else None

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest() if self._currentlyDisplayedItem else None

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse() if self._currentlyDisplayedItem else None

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.intercept_enabled or not messageIsRequest:
            return
        if toolFlag not in [self._callbacks.TOOL_PROXY, self._callbacks.TOOL_REPEATER]:
            return
        try:
            request = messageInfo.getRequest()
            analyzed = self._helpers.analyzeRequest(request)
            headers = list(analyzed.getHeaders())
            body = request[analyzed.getBodyOffset():]
            to_remove = [h.lower() for h in self.headers_to_remove]
            new_headers = [h for h in headers if h.split(":", 1)[0].strip().lower() not in to_remove]
            modified_request = self._helpers.buildHttpMessage(new_headers, body)
            httpService = messageInfo.getHttpService()
            newMessageInfo = self._callbacks.makeHttpRequest(httpService, modified_request)
            analyzedNew = self._helpers.analyzeRequest(newMessageInfo)
            method = analyzedNew.getMethod()
            url = str(analyzedNew.getUrl())
            
            # Extract status from response
            status = "N/A"
            response = newMessageInfo.getResponse()
            if response:
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers_response = analyzedResponse.getHeaders()
                if headers_response and len(headers_response) > 0:
                    status_line = headers_response[0]  # First line contains status
                    if " " in status_line:
                        status = status_line.split(" ")[1]  # Extract status code
                        print("[+] Extracted status:", status, "from:", status_line)
                    else:
                        print("[!] Invalid status line format:", status_line)
                else:
                    print("[!] No response headers found")
            else:
                print("[!] No response received")
            
            req_time = datetime.datetime.now().strftime('%H:%M:%S %m/%d/%y')
            entry = LogEntry(method, url, len(new_headers) < len(headers), req_time, newMessageInfo, status)
            self._lock.acquire()
            try:
                self.log_entries.append(entry)
                self.log_model.fireTableRowsInserted(len(self.log_entries) - 1, len(self.log_entries) - 1)
            finally:
                self._lock.release()
            self._currentlyDisplayedItem = newMessageInfo
            self._requestViewer.setMessage(newMessageInfo.getRequest(), True)
            self._responseViewer.setMessage(newMessageInfo.getResponse(), False)
        except Exception as e:
            print("[!] Intercept error:", str(e))

    def createMenuItems(self, invocation):
        """Create context menu items for right-click functionality"""
        print("[DEBUG] createMenuItems called!")
        
        try:
            responses = invocation.getSelectedMessages()
            print("[DEBUG] Selected messages count:", len(responses) if responses else 0)
            
            if responses and len(responses) > 0:
                print("[DEBUG] Creating menu item...")
                ret = LinkedList()
                requestMenuItem = JMenuItem("Send request to Header Remover")

                for response in responses:
                    requestMenuItem.addActionListener(handleMenuItems(self, response, "request"))
                ret.add(requestMenuItem)
                print("[DEBUG] Menu item added to LinkedList")
                return ret
            else:
                print("[DEBUG] No messages selected")
                return None
                
        except Exception as e:
            print("[!] Error in createMenuItems:", str(e))
            import traceback
            traceback.print_exc()
            return None

    def sendRequestToTusk(self, messageInfo):
        """Process the request sent from context menu using threading"""
        try:
            print("[+] Processing request in thread...")
            
            if messageInfo.getRequest() is None:
                print("[!] No request found in selected message")
                return
                
            # Analyze the request
            analyzed = self._helpers.analyzeRequest(messageInfo)
            method = analyzed.getMethod()
            url = str(analyzed.getUrl())
            req_time = datetime.datetime.now().strftime('%H:%M:%S %m/%d/%y')
            
            # Get status from existing response if available
            status = "N/A"
            response = messageInfo.getResponse()
            if response:
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers_response = analyzedResponse.getHeaders()
                if headers_response and len(headers_response) > 0:
                    status_line = headers_response[0]
                    if " " in status_line:
                        status = status_line.split(" ")[1]
            
            # Add to log entries
            entry = LogEntry(method, url, False, req_time, messageInfo, status)
            self._lock.acquire()
            try:
                self.log_entries.append(entry)
                self.log_model.fireTableRowsInserted(len(self.log_entries) - 1, len(self.log_entries) - 1)
            finally:
                self._lock.release()
            
            # Set as current item and display
            self._currentlyDisplayedItem = messageInfo
            self._requestViewer.setMessage(messageInfo.getRequest(), True)
            if response:
                self._responseViewer.setMessage(response, False)
            
            # Populate recent headers list for easy selection
            analyzed = self._helpers.analyzeRequest(messageInfo.getRequest())
            self.recentHeadersModel.clear()
            for h in analyzed.getHeaders():
                self.recentHeadersModel.addElement(h)
            
            print("[+] Added request to Header Remover:", method, url)
            
        except Exception as e:
            print("[!] Error in sendRequestToTusk:", str(e))
            import traceback
            traceback.print_exc()

    def clearLogs(self, event):
        """Clear all logged intercepted requests"""
        try:
            print("[+] Clear Logs button clicked!")
            print("[DEBUG] Current log entries count:", len(self.log_entries))
            
            # Clear the log entries
            self._lock.acquire()
            try:
                # Clear the list completely
                del self.log_entries[:]  # Alternative way to clear list in-place
                print("[DEBUG] Log entries cleared, new count:", len(self.log_entries))
                
                # Make sure the log model knows about the cleared list
                self.log_model.log_entries = self.log_entries
                
                # Update the table model with different fire methods
                self.log_model.fireTableDataChanged()
                # Also try firing structure changed in case the above doesn't work
                # self.log_model.fireTableStructureChanged()
                print("[DEBUG] Table model updated")
                
            finally:
                self._lock.release()
            
            # Force table to repaint
            try:
                self.log_table.repaint()
                self.log_table.revalidate()
                print("[DEBUG] Table repainted")
            except Exception as repaint_error:
                print("[DEBUG] Could not repaint table:", str(repaint_error))
            
            # Clear the recent headers list  
            self.recentHeadersModel.clear()
            print("[DEBUG] Recent headers cleared")
            
            # Clear the message viewers
            try:
                self._requestViewer.setMessage(None, True)
                self._responseViewer.setMessage(None, False)
                print("[DEBUG] Message viewers cleared")
            except:
                print("[DEBUG] Could not clear message viewers (expected if no message)")
            
            # Reset current displayed item
            self._currentlyDisplayedItem = None
            
            print("[+] All logs cleared successfully!")
            
        except Exception as e:
            print("[!] Error clearing logs:", str(e))
            import traceback
            traceback.print_exc()

class ColoredTable(JTable):
    def __init__(self, model, extender):
        JTable.__init__(self, model)
        self._extender = extender

    def prepareRenderer(self, renderer, row, column):
        comp = JTable.prepareRenderer(self, renderer, row, column)
        entry = self._extender.log_entries[row]
        if entry.header_removed:
            comp.setBackground(Color(255, 36, 0))  # light green
        else:
            comp.setBackground(Color(255, 195, 0))  # light blue
        return comp

class handleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._menuName = menuName
        self._messageInfo = messageInfo

    def actionPerformed(self, e):
        start_new_thread(self._extender.sendRequestToTusk, (self._messageInfo,))
