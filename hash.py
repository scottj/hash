#!python

from burp import (IBurpExtender, ITab)
import hashlib
import string
from javax.swing import (GroupLayout, JPanel, JTextField, JLabel, JButton, LayoutStyle)
from java.lang import (Short)

# name of extension
EXT_NAME = "Hash"

# label text
GO = "go"
MD5 = "md5"
SHA1 = "sha1"
SHA224 = "sha224"
SHA256 = "sha256"
SHA384 = "sha384"
SHA512 = "sha512"
UPPER = "upper"
LOWER = "lower"
ROT13 = "rot13"


class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)
        self.out = callbacks.getStdout()

	# define ui components
	self.tab = JPanel()
	self.p_main = JPanel()
	self.tf_source = JTextField()
	self.b_go = JButton(GO, actionPerformed=self.go)
	self.l_md5 = JLabel(MD5)
	self.l_sha1 = JLabel(SHA1)
	self.l_sha224 = JLabel(SHA224)
	self.l_sha256 = JLabel(SHA256)
	self.l_sha384 = JLabel(SHA384)
	self.l_sha512 = JLabel(SHA512)
	self.tf_md5 = JTextField()
	self.tf_sha1 = JTextField()
	self.tf_sha224 = JTextField()
	self.tf_sha256 = JTextField()
	self.tf_sha384 = JTextField()
	self.tf_sha512 = JTextField()
	self.p_buttons = JPanel()
	self.b_upper = JButton(UPPER, actionPerformed=self.toUpper)
	self.b_lower = JButton(LOWER, actionPerformed=self.toLower)
	self.b_rot13 = JButton(ROT13, actionPerformed=self.rot13)

	# setup button panel
	self.p_buttons.add(self.b_upper)
	self.p_buttons.add(self.b_lower)
	self.p_buttons.add(self.b_rot13)

	# netbeans-generated gui converted to python
        self.p_mainLayout = GroupLayout(self.p_main)
	self.p_main.setLayout(self.p_mainLayout)
        self.p_mainLayout.setHorizontalGroup(
            self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.p_mainLayout.createSequentialGroup()
                .addGap(84, 84, 84)
                .addComponent(self.tf_source, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(self.b_go)
                .addContainerGap(200, Short.MAX_VALUE))
            .addGroup(GroupLayout.Alignment.TRAILING, self.p_mainLayout.createSequentialGroup()
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.p_buttons, GroupLayout.PREFERRED_SIZE, 545, GroupLayout.PREFERRED_SIZE)
                    .addGroup(self.p_mainLayout.createSequentialGroup()
                        .addGroup(self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                            .addComponent(self.l_sha1)
                            .addComponent(self.l_sha224)
                            .addComponent(self.l_sha256)
                            .addComponent(self.l_sha384)
                            .addComponent(self.l_sha512)
                            .addComponent(self.l_md5))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                            .addComponent(self.tf_sha1)
                            .addComponent(self.tf_sha224)
                            .addComponent(self.tf_sha256)
                            .addComponent(self.tf_sha384)
                            .addComponent(self.tf_sha512, GroupLayout.DEFAULT_SIZE, 1000, Short.MAX_VALUE)
                            .addComponent(self.tf_md5))))
                .addGap(33, 33, 33))
        )
        self.p_mainLayout.setVerticalGroup(
            self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(GroupLayout.Alignment.TRAILING, self.p_mainLayout.createSequentialGroup()
                .addGap(24, 24, 24)
                .addGroup(self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.tf_source, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.b_go))
                .addGap(18, 18, 18)
                .addGroup(self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.tf_md5, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.l_md5))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.tf_sha1, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.l_sha1))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.tf_sha224, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.l_sha224))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.tf_sha256, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.l_sha256))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.tf_sha384, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.l_sha384))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.p_mainLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.tf_sha512, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.l_sha512))
                .addGap(18, 18, 18)
                .addComponent(self.p_buttons, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        )
        self.layout = GroupLayout(self.tab)
        self.tab.setLayout(self.layout)
        self.layout.setHorizontalGroup(
            self.layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self.p_main, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        )
        self.layout.setVerticalGroup(
            self.layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self.p_main, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        )

	# finalize tab
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return(EXT_NAME)

    def getUiComponent(self):
        return self.tab

    def go(self, e=None):
	text = self.tf_source.getText()
	self.tf_md5.setText(hashlib.md5(text).hexdigest())
	self.tf_sha1.setText(hashlib.sha1(text).hexdigest())
	self.tf_sha224.setText(hashlib.sha224(text).hexdigest())
	self.tf_sha256.setText(hashlib.sha256(text).hexdigest())
	self.tf_sha384.setText(hashlib.sha384(text).hexdigest())
	self.tf_sha512.setText(hashlib.sha512(text).hexdigest())

    def toUpper(self, e=None):
	self.tf_md5.setText(self.tf_md5.getText().upper())
	self.tf_sha1.setText(self.tf_sha1.getText().upper())
	self.tf_sha224.setText(self.tf_sha224.getText().upper())
	self.tf_sha256.setText(self.tf_sha256.getText().upper())
	self.tf_sha384.setText(self.tf_sha384.getText().upper())
	self.tf_sha512.setText(self.tf_sha512.getText().upper())

    def toLower(self, e=None):
	self.tf_md5.setText(self.tf_md5.getText().lower())
	self.tf_sha1.setText(self.tf_sha1.getText().lower())
	self.tf_sha224.setText(self.tf_sha224.getText().lower())
	self.tf_sha256.setText(self.tf_sha256.getText().lower())
	self.tf_sha384.setText(self.tf_sha384.getText().lower())
	self.tf_sha512.setText(self.tf_sha512.getText().lower())

    def rot13(self, e=None):
	rot13 = string.maketrans(
	    'ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz',
	    'NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm')
	self.tf_md5.setText(string.translate(self.tf_md5.getText().encode('unicode-escape'), rot13).decode('unicode-escape'))
	self.tf_sha1.setText(string.translate(self.tf_sha1.getText().encode('unicode-escape'), rot13).decode('unicode-escape'))
	self.tf_sha224.setText(string.translate(self.tf_sha224.getText().encode('unicode-escape'), rot13).decode('unicode-escape'))
	self.tf_sha256.setText(string.translate(self.tf_sha256.getText().encode('unicode-escape'), rot13).decode('unicode-escape'))
	self.tf_sha384.setText(string.translate(self.tf_sha384.getText().encode('unicode-escape'), rot13).decode('unicode-escape'))
	self.tf_sha512.setText(string.translate(self.tf_sha512.getText().encode('unicode-escape'), rot13).decode('unicode-escape'))
