# Form implementation generated from reading ui file 'updatedWindow.ui'
#
# Created by: PyQt6 UI code generator 6.4.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets

import matplotlib
matplotlib.use('QT5Agg')

import user_steps as us

from matplotlib.backends.backend_qt5agg import (
    FigureCanvasQTAgg, FigureCanvas, NavigationToolbar2QT as NavigationToolbar)
from matplotlib.figure import Figure

import matplotlib.pyplot as plt

from mplwidget import MplWidget, MplCanvas

import os

class MplCanvas(FigureCanvasQTAgg):

    def __init__(self, parent=None, width=5, height=4, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        super(MplCanvas, self).__init__(fig)


class Ui_MainWindow(object):
    def __init__(self):
        self.trainFileFound = False
        self.targetFileFound = False
        self.trainingfile = ''
        self.targetfile = ''
        self.modelNames = []
        self.trainResults = []
        self.oModelNames = []
        self.oResults = []

        
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(669, 600)
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        # Widget containing Set up information
        self.SetUpWIDGET = QtWidgets.QTabWidget(parent=self.centralwidget)
        self.SetUpWIDGET.setGeometry(QtCore.QRect(10, 70, 641, 161))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.SetUpWIDGET.setFont(font)
        self.SetUpWIDGET.setFocusPolicy(QtCore.Qt.FocusPolicy.TabFocus)
        self.SetUpWIDGET.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.DefaultContextMenu)
        self.SetUpWIDGET.setTabPosition(QtWidgets.QTabWidget.TabPosition.North)
        self.SetUpWIDGET.setTabShape(QtWidgets.QTabWidget.TabShape.Rounded)
        self.SetUpWIDGET.setElideMode(QtCore.Qt.TextElideMode.ElideRight)
        self.SetUpWIDGET.setUsesScrollButtons(False)
        self.SetUpWIDGET.setDocumentMode(True)
        self.SetUpWIDGET.setTabsClosable(False)
        self.SetUpWIDGET.setMovable(False)
        self.SetUpWIDGET.setObjectName("SetUpWIDGET")

        # Tab for Selecting best model
        self.SelectionTAB = QtWidgets.QWidget()
        self.SelectionTAB.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.SelectionTAB.setObjectName("SelectionTAB")

        self.TrainingFileLABEL = QtWidgets.QLabel(parent=self.SelectionTAB)
        self.TrainingFileLABEL.setGeometry(QtCore.QRect(20, 10, 101, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.TrainingFileLABEL.setFont(font)
        self.TrainingFileLABEL.setLayoutDirection(QtCore.Qt.LayoutDirection.RightToLeft)
        self.TrainingFileLABEL.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.TrainingFileLABEL.setObjectName("TrainingFileLABEL")\

        self.TargetFileLABEL = QtWidgets.QLabel(parent=self.SelectionTAB)
        self.TargetFileLABEL.setGeometry(QtCore.QRect(20, 40, 101, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.TargetFileLABEL.setFont(font)
        self.TargetFileLABEL.setLayoutDirection(QtCore.Qt.LayoutDirection.RightToLeft)
        self.TargetFileLABEL.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.TargetFileLABEL.setObjectName("TargetFileLABEL")

        # Input for training file
        self.trainingFileINPUT = QtWidgets.QLineEdit(parent=self.SelectionTAB)
        self.trainingFileINPUT.setGeometry(QtCore.QRect(130, 10, 371, 21))
        self.trainingFileINPUT.setObjectName("trainingFileINPUT")
        # Training File input changed - call function
        self.trainingFileINPUT.textChanged.connect(self.fileExists)

        # Input for the target file
        self.targetfileINPUT = QtWidgets.QLineEdit(parent=self.SelectionTAB)
        self.targetfileINPUT.setGeometry(QtCore.QRect(130, 40, 371, 21))
        self.targetfileINPUT.setObjectName("targetfileINPUT")
        # Target file input changed - call function
        self.targetfileINPUT.textChanged.connect(self.fileExists)
        

        # Status Labels to tell user if file is found
        self.trainingFileStatusLABEL = QtWidgets.QLabel(parent=self.SelectionTAB)
        self.trainingFileStatusLABEL.setEnabled(False)
        self.trainingFileStatusLABEL.setGeometry(QtCore.QRect(530, 10, 101, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.trainingFileStatusLABEL.setFont(font)
        self.trainingFileStatusLABEL.setStyleSheet("color : rgb(255, 66, 60)")
        self.trainingFileStatusLABEL.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.trainingFileStatusLABEL.setObjectName("trainingFileStatusLABEL")

        self.TargetsFileStatusLABEL = QtWidgets.QLabel(parent=self.SelectionTAB)
        self.TargetsFileStatusLABEL.setEnabled(False)
        self.TargetsFileStatusLABEL.setGeometry(QtCore.QRect(530, 40, 101, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.TargetsFileStatusLABEL.setFont(font)
        self.TargetsFileStatusLABEL.setStyleSheet("color : rgb(255, 66, 60)")
        self.TargetsFileStatusLABEL.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.TargetsFileStatusLABEL.setObjectName("TargetsFileStatusLABEL")

        # Start button to begin training
        self.StartBUTTON = QtWidgets.QPushButton(parent=self.SelectionTAB)
        self.StartBUTTON.setEnabled(False)
        self.StartBUTTON.setGeometry(QtCore.QRect(530, 100, 100, 32))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.StartBUTTON.setFont(font)
        self.StartBUTTON.setObjectName("StartBUTTON")
        # When Start button is pressed
        self.StartBUTTON.clicked.connect(self.handleStory)

        # Check button to include preprocessing steps
        self.PreprocessingCHECK = QtWidgets.QCheckBox(parent=self.SelectionTAB)
        self.PreprocessingCHECK.setGeometry(QtCore.QRect(60, 70, 441, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.PreprocessingCHECK.setFont(font)
        self.PreprocessingCHECK.setLayoutDirection(QtCore.Qt.LayoutDirection.RightToLeft)
        self.PreprocessingCHECK.setObjectName("PreprocessingCHECK")

        # Check to provide intial Training Outputs - REMOVE????
        self.trainingSummariesCHECK = QtWidgets.QCheckBox(parent=self.SelectionTAB)
        self.trainingSummariesCHECK.setGeometry(QtCore.QRect(260, 100, 241, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.trainingSummariesCHECK.setFont(font)
        self.trainingSummariesCHECK.setLayoutDirection(QtCore.Qt.LayoutDirection.RightToLeft)
        self.trainingSummariesCHECK.setObjectName("trainingSummariesCHECK")


        # TAB For Live Detection
        self.SetUpWIDGET.addTab(self.SelectionTAB, "")
        self.LiveTAB = QtWidgets.QWidget()
        self.LiveTAB.setObjectName("LiveTAB")
        self.SetUpWIDGET.addTab(self.LiveTAB, "")


        # Output WIDGET at the bottom of the SCREEN
        self.graphOutputWIDGET = QtWidgets.QWidget(parent=self.centralwidget)
        self.graphOutputWIDGET.setEnabled(False)
        self.graphOutputWIDGET.setGeometry(QtCore.QRect(10, 270, 641, 271))
        self.graphOutputWIDGET.setObjectName("graphOutputWIDGET")

        # TAB WIDGET for different graphs based on metrics 
        self.tabWidget = QtWidgets.QTabWidget(parent=self.graphOutputWIDGET)
        self.tabWidget.setGeometry(QtCore.QRect(-1, -1, 381, 261))
        self.tabWidget.setTabPosition(QtWidgets.QTabWidget.TabPosition.East)
        self.tabWidget.setTabShape(QtWidgets.QTabWidget.TabShape.Triangular)
        self.tabWidget.setElideMode(QtCore.Qt.TextElideMode.ElideNone)
        self.tabWidget.setUsesScrollButtons(True)
        self.tabWidget.setDocumentMode(False)
        self.tabWidget.setTabsClosable(False)
        self.tabWidget.setMovable(True)
        self.tabWidget.setObjectName("tabWidget")

        self.TimeTAB = QtWidgets.QWidget()
        self.TimeTAB.setObjectName("TimeTAB")
        self.timeOutputLABEL = QtWidgets.QLabel(parent=self.TimeTAB)
        self.timeOutputLABEL.setGeometry(QtCore.QRect(20, 20, 311, 211))
        self.timeOutputLABEL.setObjectName("timeOutputLABEL")
        self.tabWidget.addTab(self.TimeTAB, "")


        self.PrecisionTAB = QtWidgets.QWidget()
        self.PrecisionTAB.setObjectName("PrecisionTAB")
        self.precisionOutputLABEL = QtWidgets.QLabel(parent=self.PrecisionTAB)
        self.precisionOutputLABEL.setGeometry(QtCore.QRect(20, 20, 311, 211))
        self.precisionOutputLABEL.setObjectName("precisionOutputLABEL")
        self.tabWidget.addTab(self.PrecisionTAB, "")


        self.RecallTAB = QtWidgets.QWidget()
        self.RecallTAB.setObjectName("RecallTAB")
        self.recallOutputLABEL = QtWidgets.QLabel(parent=self.RecallTAB)
        self.recallOutputLABEL.setGeometry(QtCore.QRect(20, 20, 311, 211))
        self.recallOutputLABEL.setObjectName("recallOutputLABEL")
        self.tabWidget.addTab(self.RecallTAB, "")


        self.F1TAB = QtWidgets.QWidget()
        self.F1TAB.setObjectName("F1TAB")
        self.f1OutputLABEL = QtWidgets.QLabel(parent=self.F1TAB)
        self.f1OutputLABEL.setGeometry(QtCore.QRect(20, 20, 311, 211))
        self.f1OutputLABEL.setObjectName("f1OutputLABEL")
        self.tabWidget.addTab(self.F1TAB, "")


        self.OutputLABEL = QtWidgets.QLabel(parent=self.graphOutputWIDGET)
        self.OutputLABEL.setGeometry(QtCore.QRect(400, 0, 221, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(14)
        font.setBold(True)
        self.OutputLABEL.setFont(font)
        self.OutputLABEL.setObjectName("OutputLABEL")
        self.optimisationCHECK = QtWidgets.QCheckBox(parent=self.graphOutputWIDGET)
        self.optimisationCHECK.setGeometry(QtCore.QRect(400, 60, 231, 20))
        self.optimisationCHECK.setObjectName("optimisationCHECK")
        self.TrainingCHECK = QtWidgets.QCheckBox(parent=self.graphOutputWIDGET)
        self.TrainingCHECK.setGeometry(QtCore.QRect(400, 30, 231, 20))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.TrainingCHECK.setFont(font)
        self.TrainingCHECK.setObjectName("TrainingCHECK")
        self.BestCHECK = QtWidgets.QCheckBox(parent=self.graphOutputWIDGET)
        self.BestCHECK.setGeometry(QtCore.QRect(400, 90, 221, 20))
        self.BestCHECK.setObjectName("BestCHECK")
        self.UpdateGraphBUTTON = QtWidgets.QPushButton(parent=self.graphOutputWIDGET)
        self.UpdateGraphBUTTON.setGeometry(QtCore.QRect(530, 110, 100, 32))
        self.UpdateGraphBUTTON.setObjectName("UpdateGraphBUTTON")
        self.statsTEXTBOX = QtWidgets.QTextBrowser(parent=self.graphOutputWIDGET)
        self.statsTEXTBOX.setGeometry(QtCore.QRect(400, 150, 231, 111))
        self.statsTEXTBOX.setObjectName("statsTEXTBOX")
        self.SetUpLABEL = QtWidgets.QLabel(parent=self.centralwidget)
        self.SetUpLABEL.setGeometry(QtCore.QRect(10, 40, 411, 21))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(14)
        font.setBold(True)
        self.SetUpLABEL.setFont(font)
        self.SetUpLABEL.setObjectName("SetUpLABEL")
        self.OutputSectionLABEL = QtWidgets.QLabel(parent=self.centralwidget)
        self.OutputSectionLABEL.setEnabled(True)
        self.OutputSectionLABEL.setGeometry(QtCore.QRect(10, 240, 411, 31))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(14)
        font.setBold(True)
        self.OutputSectionLABEL.setFont(font)
        self.OutputSectionLABEL.setObjectName("OutputSectionLABEL")
        self.TitleLABEL = QtWidgets.QLabel(parent=self.centralwidget)
        self.TitleLABEL.setGeometry(QtCore.QRect(10, 0, 641, 31))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(20)
        font.setBold(True)
        self.TitleLABEL.setFont(font)
        self.TitleLABEL.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.TitleLABEL.setObjectName("TitleLABEL")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 669, 24))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.TrainingFileLABEL.setBuddy(self.trainingFileINPUT)
        self.TargetFileLABEL.setBuddy(self.targetfileINPUT)

        self.retranslateUi(MainWindow)
        self.SetUpWIDGET.setCurrentIndex(0)
        self.tabWidget.setCurrentIndex(2)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.TrainingFileLABEL.setText(_translate("MainWindow", "Training File:"))
        self.TargetFileLABEL.setText(_translate("MainWindow", "Target Class File:"))
        self.trainingFileStatusLABEL.setText(_translate("MainWindow", "file not found"))
        self.TargetsFileStatusLABEL.setText(_translate("MainWindow", "file not found"))
        self.StartBUTTON.setText(_translate("MainWindow", "Start"))
        self.PreprocessingCHECK.setText(_translate("MainWindow", "Include Data Preprocessing     "))
        self.trainingSummariesCHECK.setText(_translate("MainWindow", "Provide Training Summaries     "))
        self.SetUpWIDGET.setTabText(self.SetUpWIDGET.indexOf(self.SelectionTAB), _translate("MainWindow", "Model Selection"))
        self.SetUpWIDGET.setTabText(self.SetUpWIDGET.indexOf(self.LiveTAB), _translate("MainWindow", "Live Monitoring"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.TimeTAB), _translate("MainWindow", "Time"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.PrecisionTAB), _translate("MainWindow", "Precision"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.RecallTAB), _translate("MainWindow", "Recall"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.F1TAB), _translate("MainWindow", "F1"))
        self.OutputLABEL.setText(_translate("MainWindow", "Show Data For:"))
        self.optimisationCHECK.setText(_translate("MainWindow", "     Best Models Optimisations"))
        self.TrainingCHECK.setText(_translate("MainWindow", "     Initial Training"))
        self.BestCHECK.setText(_translate("MainWindow", "     Best Model"))
        self.UpdateGraphBUTTON.setText(_translate("MainWindow", "Update"))
        self.SetUpLABEL.setText(_translate("MainWindow", "Select the action you want"))
        self.OutputSectionLABEL.setText(_translate("MainWindow", "Output Results"))
        self.TitleLABEL.setText(_translate("MainWindow", "Network IDS Tool"))

    '''
    Function checks if training/target files exist
    Updates Status labels and backend logic
    Also controls visibility of the start button
    '''
    def fileExists(self):
        # Make Status labels visible
        self.trainingFileStatusLABEL.setEnabled(True)
        self.TargetsFileStatusLABEL.setEnabled(True)

        if os.path.isfile(self.trainingFileINPUT.text()):
            # Update colour and text for user
            self.trainingFileStatusLABEL.setStyleSheet("color : rgb(89, 224, 61)")
            self.trainingFileStatusLABEL.setText("File Found!")

            self.trainFileFound = True
            self.trainingfile = self.trainingFileINPUT.text()
        else:
            self.trainingFileStatusLABEL.setStyleSheet("color : rgb(255, 66, 60)")
            self.trainingFileStatusLABEL.setText("File Not Found")
            self.trainFileFound = False

        if os.path.isfile(self.targetfileINPUT.text()):
            # Update colour and text for user
            self.TargetsFileStatusLABEL.setStyleSheet("color: rgb(89, 224, 61)")
            self.TargetsFileStatusLABEL.setText("File Found!")

            self.targetFileFound = True
            self.targetfile = self.targetfileINPUT.text()
        else:
            self.TargetsFileStatusLABEL.setStyleSheet("color : rgb(255, 66, 60)")
            self.TargetsFileStatusLABEL.setText("File Not Found")
            self.targetFileFound = False
    
        if self.trainFileFound == True and self.targetFileFound == True:
            self.StartBUTTON.setEnabled(True)

        return
    
    def handleStory(self):
        if self.PreprocessingCHECK.isChecked():
            self.modelNames, self.trainResults, self.oModelNames, self.oResults = us.fullToLive(self.trainingfile, self.targetfile)
        else:
            self.modelNames, selt.trainResults, self.oModelNames, self.oResults = us.modelSelectionNoProcessing(self.trainingfile, self.targetfile)

        print(self.trainResults)
        print(self.oModelNames[0])

        # Enable the output window
        self.graphOutputWIDGET.setEnabled(True)
    
    def plot(self):
        ax.self.figure.add_subplot(111)

        trainResults = 0
        ax.boxplot(results,patch_artist=True,boxprops = dict(linestyle='-', linewidth=1, color='tab:pink', facecolor= 'tab:pink'), whiskerprops={"color": 'k', "linewidth": 1.5}, capprops={"color": 'k',  "linewidth": 1.5},  medianprops={"color": "k", "linewidth": 1})



