'''
IDS Builder 
April 2023
Jude Campbell - 2382182c

GUI 
    file contains code to open the GUI for use.
    GUI required updatedWindow.py which is where UI 
    features are defined. 
'''
import sys
from PyQt6 import QtWidgets, uic

#from MainWindow import Ui_MainWindow
from updatedWindow import Ui_MainWindow


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, *args, obj=None, **kwargs):
        super(MainWindow, self).__init__(*args, **kwargs)
        self.setupUi(self)

app = QtWidgets.QApplication(sys.argv)

window = MainWindow()
window.show()
app.exec()
