#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JLabel, JToggleButton, JTextField, JScrollPane, JList, DefaultListModel, JButton
from burp import ITab
from burp import IBurpExtender
from burp import IHttpListener
from burp import IContextMenuFactory
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from burp import IHttpRequestResponseWithMarkers
from burp import IHttpService
from burp import ITextEditor
from javax.swing import JList
from javax.swing import JTable
from javax.swing import JFrame
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JToggleButton
from javax.swing import JCheckBox
from javax.swing import JMenuItem
from javax.swing import JTextArea
from javax.swing import JTree
from javax.swing.tree import TreePath
from javax.swing import JPopupMenu
from javax.swing import JSplitPane
from javax.swing import JEditorPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import SwingUtilities
from javax.swing.table import TableRowSorter
from javax.swing.table import AbstractTableModel
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import DefaultTreeCellRenderer
from javax.swing.tree import DefaultTreeModel
from javax.swing.text.html import HTMLEditorKit
from threading import Lock
from java.io import File
from java.net import URL
from java.net import URLEncoder
from java.awt import Color
from java.awt import Dimension
from java.awt import BorderLayout
from java.awt.event import MouseAdapter
from java.awt.event import ActionListener
from java.awt.event import AdjustmentListener
from java.util import LinkedList
from java.util import ArrayList
from java.lang import Runnable
from java.lang import Integer
from java.lang import String
from java.lang import Math
from thread import start_new_thread
from array import array
import datetime
import re


class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Header Remover")
        self.intercept = 0
        self._lock = Lock()
        self.headers_to_remove = []  # List of headers to remove
        self.initConfigTab()
        self._callbacks.registerHttpListener(self)
        self._callbacks.addSuiteTab(self)
        self._log = ArrayList()
        #_log used to store our outputs for a URL, which is retrieved later by the tool

        self._lock = Lock()
        #Lock is used for locking threads while updating logs in order such that no multiple updates happen at once
        
        self.intercept = 0

        self.FOUND = "Found"
        self.CHECK = "Possible! Check Manually"
        self.NOT_FOUND = "Not Found"
        #Static Values for output


        #Initialize GUI

        self.advisoryReqResp()

        self.configTab()

        self.tabsInit()

        self.definecallbacks()
        print("Thank You for Installing Header Remover")
        return

    def initConfigTab(self):
        self.configtab = JPanel()
        self.configtab.setLayout(None)
        self.configtab.setBounds(0, 0, 500, 400)

        label = JLabel("Headers to Remove:")
        label.setBounds(40, 10, 200, 30)
        self.configtab.add(label)

        # List to display headers to remove
        self.headerListModel = DefaultListModel()
        self.headerList = JList(self.headerListModel)
        scrollHeaderList = JScrollPane(self.headerList)
        scrollHeaderList.setBounds(40, 40, 200, 80)
        self.configtab.add(scrollHeaderList)

        # Button to remove selected header from the list
        self.removeHeaderButton = JButton("Remove Selected Header", actionPerformed=self.removeSelectedHeader)
        self.removeHeaderButton.setBounds(260, 40, 180, 30)
        self.configtab.add(self.removeHeaderButton)

        # Toggle button for intercept
        self.startButton = JToggleButton("Intercept Off", actionPerformed=self.startOrStop)
        self.startButton.setBounds(40, 130, 200, 30)
        self.configtab.add(self.startButton)

        # Label and list for most recent intercepted request's headers
        self.reqLabel = JLabel("Most Recent Request Headers:")
        self.reqLabel.setBounds(40, 170, 250, 30)
        self.configtab.add(self.reqLabel)

        self.recentHeadersModel = DefaultListModel()
        self.recentHeadersList = JList(self.recentHeadersModel)
        scrollRecentHeaders = JScrollPane(self.recentHeadersList)
        scrollRecentHeaders.setBounds(40, 200, 400, 80)
        self.configtab.add(scrollRecentHeaders)

        # Button to add selected header from intercepted request to remove list
        self.addHeaderButton = JButton("Add Selected Header to Remove List", actionPerformed=self.addSelectedHeader)
        self.addHeaderButton.setBounds(40, 290, 300, 30)
        self.configtab.add(self.addHeaderButton)

    def advisoryReqResp(self):
        self.textfield = JEditorPane("text/html", "")
        self.kit = HTMLEditorKit()
        self.textfield.setEditorKit(self.kit)
        self.doc = self.textfield.getDocument()
        self.textfield.setEditable(0)
        self.advisorypanel = JScrollPane()
        self.advisorypanel.getVerticalScrollBar()
        self.advisorypanel.setPreferredSize(Dimension(300,450))
        self.advisorypanel.getViewport().setView((self.textfield))

        self.selectedreq = []

        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)
        self._texteditor = self._callbacks.createTextEditor()
        self._texteditor.setEditable(False)

    def startOrStop(self, event):
        if self.startButton.getText() == "Intercept Off":
            self.startButton.setText("Intercept On")
            self.startButton.setSelected(True)
            self.intercept = 1
        else:
            self.startButton.setText("Intercept Off")
            self.startButton.setSelected(False)
            self.intercept = 0

    def removeSelectedHeader(self, event):
        selected = self.headerList.getSelectedValue()
        if selected and selected in self.headers_to_remove:
            self.headers_to_remove.remove(selected)
            self.headerListModel.removeElement(selected)

    def addSelectedHeader(self, event):
        selected = self.recentHeadersList.getSelectedValue()
        if selected:
            header_name = selected.split(":", 1)[0].strip()
            if header_name and header_name not in self.headers_to_remove:
                self.headers_to_remove.append(header_name)
                self.headerListModel.addElement(header_name)

    def getTabCaption(self):
        return "Header Remover"

    def getUiComponent(self):
        return self.configtab

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self.intercept == 1 and messageIsRequest:
            request = messageInfo.getRequest()
            analyzedRequest = self._helpers.analyzeRequest(request)
            headers = list(analyzedRequest.getHeaders())

            # Update recentHeadersModel with current request's headers
            self.recentHeadersModel.clear()
            for h in headers:
                self.recentHeadersModel.addElement(h)

            # Remove all headers in headers_to_remove (case-insensitive)
            to_remove = [h.lower() for h in self.headers_to_remove]
            new_headers = [h for h in headers if h.split(":",1)[0].strip().lower() not in to_remove]
            body = request[analyzedRequest.getBodyOffset():]
            new_request = self._helpers.buildHttpMessage(new_headers, body)
            messageInfo.setRequest(new_request)