'''
IDS Builder 
April 2023
Jude Campbell - 2382182c

.py file containing UI formatting and conntection
file is based on updatedWindow.ui


'''
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtGui import QPixmap
from PIL import Image, ImageQt
import matplotlib as mpl
print(mpl.get_cachedir)
import user_steps as us

from matplotlib.backends.backend_qt5agg import (
    FigureCanvasQTAgg, FigureCanvas, NavigationToolbar2QT as NavigationToolbar)
from matplotlib.figure import Figure

import matplotlib.pyplot as plt

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
        self.size = 0

        
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(669, 900)
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        # Widget containing Set up information
        self.SetUpWIDGET = QtWidgets.QTabWidget(parent=self.centralwidget)
        self.SetUpWIDGET.setGeometry(QtCore.QRect(10, 70, 641, 781))
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
        self.graphOutputWIDGET = QtWidgets.QWidget(parent=self.SelectionTAB)
        self.graphOutputWIDGET.setEnabled(True)
        self.graphOutputWIDGET.setGeometry(QtCore.QRect(0, 150, 641, 601))
        self.graphOutputWIDGET.setObjectName("graphOutputWIDGET")

        # TAB WIDGET for different graphs based on metrics 
        self.tabWidget = QtWidgets.QTabWidget(parent=self.graphOutputWIDGET)
        self.tabWidget.setGeometry(QtCore.QRect(10, 100, 631, 501))
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

        self.scene = QtWidgets.QGraphicsScene()

        self.timeOutputLABEL = QtWidgets.QLabel(parent=self.TimeTAB)
        self.timeOutputLABEL.setGeometry(QtCore.QRect(10, 10, 581, 411))
        self.timeOutputLABEL.setObjectName("timeOutputLABEL")
        self.tabWidget.addTab(self.TimeTAB, "")


        self.PrecisionTAB = QtWidgets.QWidget()
        self.PrecisionTAB.setObjectName("PrecisionTAB")
        self.precisionOutputLABEL = QtWidgets.QLabel(parent=self.PrecisionTAB)
        self.precisionOutputLABEL.setGeometry(QtCore.QRect(10, 10, 581, 411))
        self.precisionOutputLABEL.setObjectName("precisionOutputLABEL")
        self.tabWidget.addTab(self.PrecisionTAB, "")


        self.RecallTAB = QtWidgets.QWidget()
        self.RecallTAB.setObjectName("RecallTAB")
        self.recallOutputLABEL = QtWidgets.QLabel(parent=self.RecallTAB)
        self.recallOutputLABEL.setGeometry(QtCore.QRect(10, 10, 581, 411))
        self.recallOutputLABEL.setObjectName("recallOutputLABEL")
        self.tabWidget.addTab(self.RecallTAB, "")


        self.F1TAB = QtWidgets.QWidget()
        self.F1TAB.setObjectName("F1TAB")
        self.f1OutputLABEL = QtWidgets.QLabel(parent=self.F1TAB)
        self.f1OutputLABEL.setGeometry(QtCore.QRect(10, 10, 581, 411))
        self.f1OutputLABEL.setObjectName("f1OutputLABEL")
        self.tabWidget.addTab(self.F1TAB, "")

        self.evalTimeTAB = QtWidgets.QWidget()
        self.evalTimeTAB.setObjectName("evalTimeTAB")
        self.evalTimeTABOutputLABEL = QtWidgets.QLabel(parent=self.evalTimeTAB)
        self.evalTimeTABOutputLABEL.setGeometry(QtCore.QRect(10, 10, 581, 411))
        self.evalTimeTABOutputLABEL.setObjectName("evalTimeTABOutputLABEL")
        self.tabWidget.addTab(self.evalTimeTAB, "")

        self.balAccTAB = QtWidgets.QWidget()
        self.balAccTAB.setObjectName("balAccTAB")
        self.balAccTabOutputLABEL = QtWidgets.QLabel(parent=self.balAccTAB)
        self.balAccTabOutputLABEL.setGeometry(QtCore.QRect(10, 10, 581, 411))
        self.balAccTabOutputLABEL.setObjectName("balAccTabOutputLABEL")
        self.tabWidget.addTab(self.balAccTAB, "")


        # Label that says output for: 
        self.OutputLABEL = QtWidgets.QLabel(parent=self.graphOutputWIDGET)
        self.OutputLABEL.setGeometry(QtCore.QRect(10, 0, 221, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(14)
        font.setBold(True)
        self.OutputLABEL.setFont(font)
        self.OutputLABEL.setObjectName("OutputLABEL")
        
        # Check to show Optimisation graphs
        self.optimisationCHECK = QtWidgets.QCheckBox(parent=self.graphOutputWIDGET)
        self.optimisationCHECK.setGeometry(QtCore.QRect(150, 20, 200, 31))
        self.optimisationCHECK.setObjectName("optimisationCHECK")

        self.TrainingCHECK = QtWidgets.QCheckBox(parent=self.graphOutputWIDGET)
        self.TrainingCHECK.setGeometry(QtCore.QRect(10, 20, 151, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.TrainingCHECK.setFont(font)
        self.TrainingCHECK.setObjectName("TrainingCHECK")

        self.BestCHECK = QtWidgets.QCheckBox(parent=self.graphOutputWIDGET)
        self.BestCHECK.setGeometry(QtCore.QRect(380, 20, 111, 31))
        self.BestCHECK.setObjectName("BestCHECK")

        self.UpdateGraphBUTTON = QtWidgets.QPushButton(parent=self.graphOutputWIDGET)
        self.UpdateGraphBUTTON.setGeometry(QtCore.QRect(520, 20, 100, 32))
        self.UpdateGraphBUTTON.setObjectName("UpdateGraphBUTTON")
        self.UpdateGraphBUTTON.clicked.connect(self.updateOutput)

        self.OUTPUTstats = QtWidgets.QTextBrowser(parent=self.graphOutputWIDGET)
        self.OUTPUTstats.setGeometry(QtCore.QRect(10, 50, 611, 51))
        self.OUTPUTstats.setObjectName("OUTPUTstats")

        self.SetUpLABEL = QtWidgets.QLabel(parent=self.centralwidget)
        self.SetUpLABEL.setGeometry(QtCore.QRect(10, 40, 411, 21))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(14)
        font.setBold(True)
        self.SetUpLABEL.setFont(font)
        self.SetUpLABEL.setObjectName("SetUpLABEL")

        self.OutputSectionLABEL = QtWidgets.QLabel(parent=self.SelectionTAB)
        self.OutputSectionLABEL.setEnabled(True)
        self.OutputSectionLABEL.setGeometry(QtCore.QRect(10, 120, 411, 31))
        font = QtGui.QFont()
        font.setFamily("Arial Black")
        font.setPointSize(14)
        font.setBold(True)
        self.OutputSectionLABEL.setFont(font)
        self.OutputSectionLABEL.setObjectName("OutputSectionLABEL")

        self.ModelFileLABEL = QtWidgets.QLabel(parent=self.LiveTAB)
        self.ModelFileLABEL.setGeometry(QtCore.QRect(20, 10, 101, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.ModelFileLABEL.setFont(font)
        self.ModelFileLABEL.setLayoutDirection(QtCore.Qt.LayoutDirection.RightToLeft)
        self.ModelFileLABEL.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.ModelFileLABEL.setObjectName("ModelFileLABEL")
        self.timestampFreqLABEL = QtWidgets.QLabel(parent=self.LiveTAB)
        self.timestampFreqLABEL.setGeometry(QtCore.QRect(20, 40, 101, 21))
        font = QtGui.QFont()
        font.setFamily("Arial")
        self.timestampFreqLABEL.setFont(font)
        self.timestampFreqLABEL.setLayoutDirection(QtCore.Qt.LayoutDirection.RightToLeft)
        self.timestampFreqLABEL.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.timestampFreqLABEL.setObjectName("timestampFreqLABEL")
        self.modelFileINPUT = QtWidgets.QLineEdit(parent=self.LiveTAB)
        self.modelFileINPUT.setGeometry(QtCore.QRect(130, 10, 371, 21))
        self.modelFileINPUT.setObjectName("modelFileINPUT")
        self.freqINPUT = QtWidgets.QLineEdit(parent=self.LiveTAB)
        self.freqINPUT.setGeometry(QtCore.QRect(130, 40, 371, 21))
        self.freqINPUT.setText("")
        self.freqINPUT.setObjectName("freqINPUT")
        self.attackDetecOUTPUT = QtWidgets.QTextBrowser(parent=self.LiveTAB)
        self.attackDetecOUTPUT.setGeometry(QtCore.QRect(10, 120, 621, 211))
        self.attackDetecOUTPUT.setObjectName("attackDetecOUTPUT")
        self.startLiveBUTTON = QtWidgets.QPushButton(parent=self.LiveTAB)
        self.startLiveBUTTON.setGeometry(QtCore.QRect(500, 70, 131, 31))
        self.startLiveBUTTON.setObjectName("startLiveBUTTON")
        self.startLiveBUTTON.clicked.connect(self.liveDetections)
        self.SetUpWIDGET.addTab(self.LiveTAB, "")
    
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
        self.ModelFileLABEL.setBuddy(self.trainingFileINPUT)
        self.timestampFreqLABEL.setBuddy(self.targetfileINPUT)

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
        self.trainingSummariesCHECK.setText(_translate("MainWindow", "Labels are in datafile     "))
        self.SetUpWIDGET.setTabText(self.SetUpWIDGET.indexOf(self.SelectionTAB), _translate("MainWindow", "Model Selection"))
        self.SetUpWIDGET.setTabText(self.SetUpWIDGET.indexOf(self.LiveTAB), _translate("MainWindow", "Live Monitoring"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.TimeTAB), _translate("MainWindow", "Time"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.PrecisionTAB), _translate("MainWindow", "Precision"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.RecallTAB), _translate("MainWindow", "Recall"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.F1TAB), _translate("MainWindow", "F1"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.evalTimeTAB), _translate("MainWindow", "Eval Time"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.balAccTAB), _translate("MainWindow", "Balanced Acc"))
        self.OutputLABEL.setText(_translate("MainWindow", "Show Data For:"))
        self.optimisationCHECK.setText(_translate("MainWindow", "     Best Models Optimisations"))
        self.TrainingCHECK.setText(_translate("MainWindow", "     Initial Training"))
        self.BestCHECK.setText(_translate("MainWindow", "     Best Model"))
        self.UpdateGraphBUTTON.setText(_translate("MainWindow", "Update"))
        self.SetUpLABEL.setText(_translate("MainWindow", "Select the action you want"))
        self.ModelFileLABEL.setText(_translate("MainWindow", "Model File:"))
        self.timestampFreqLABEL.setText(_translate("MainWindow", "Frequency:"))
        self.attackDetecOUTPUT.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"hr { height: 1px; border-width: 0; }\n"
"li.unchecked::marker { content: \"\\2610\"; }\n"
"li.checked::marker { content: \"\\2612\"; }\n"
"</style></head><body style=\" font-family:\'Arial\'; font-size:13pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Attack Detection Output</p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.startLiveBUTTON.setText(_translate("MainWindow", "Start Live Detection"))
        self.SetUpWIDGET.setTabText(self.SetUpWIDGET.indexOf(self.LiveTAB), _translate("MainWindow", "Live Monitoring"))
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
        elif self.trainFileFound == True and self.trainingSummariesCHECK.isChecked() == True:
            self.StartBUTTON.setEnabled(True)
        else:
            self.StartBUTTON.setEnabled(False)

        return

    def showPlots(self):
        self.tabWidget.setTabVisible(self.tabWidget.indexOf(self.F1TAB), True)
        self.tabWidget.setTabVisible(self.tabWidget.indexOf(self.balAccTAB), True)
        # Eval times
        image_profile = QtGui.QImage('figures/TrainingEvalTimeStackedBars.png') #QImage object
        image_profile = image_profile.scaled(self.evalTimeTABOutputLABEL.width(), self.evalTimeTABOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.evalTimeTABOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile)) 
        self.evalTimeTABOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.evalTimeTAB), ("Eval Time"))
        # Training Times
        image_profile2 = QtGui.QImage('figures/TrainingTimeSeperateBars.png') #QImage object
        image_profile2 = image_profile2.scaled(self.timeOutputLABEL.width() ,self.timeOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.timeOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile2)) 
        self.timeOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.TimeTAB), ("Time"))
        # Recall
        image_profile3 = QtGui.QImage('figures/TrainingRecallLineGraph.png') #QImage object
        image_profile3 = image_profile3.scaled(self.recallOutputLABEL.width() ,self.recallOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.recallOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile3)) 
        self.recallOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.RecallTAB), ("Recall"))

        image_profile4 = QtGui.QImage('figures/TrainingPrecisionBoxPlots.png') #QImage object
        image_profile4 = image_profile4.scaled(self.precisionOutputLABEL.width() ,self.precisionOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.precisionOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile4)) 
        self.precisionOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.PrecisionTAB), ("Precision"))

        image_profile5 = QtGui.QImage('figures/Trainingf1BoxPlots.png') #QImage object
        image_profile5 = image_profile5.scaled(self.f1OutputLABEL.width() ,self.f1OutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.f1OutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile5)) 
        self.f1OutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")

        image_profile6 = QtGui.QImage('figures/TrainingBalancedAccuracyBoxPlots.png') #QImage object
        image_profile6 = image_profile6.scaled(self.balAccTabOutputLABEL.width() ,self.balAccTabOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.balAccTabOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile6)) 
        self.balAccTabOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")

    def OptimisationPlots(self):
        self.tabWidget.setTabVisible(self.tabWidget.indexOf(self.F1TAB), True)
        self.tabWidget.setTabVisible(self.tabWidget.indexOf(self.balAccTAB), True)
        # Eval times
        image_profile = QtGui.QImage('figures/OptimisedEvalTimeStackedBars.png') #QImage object
        image_profile = image_profile.scaled(self.evalTimeTABOutputLABEL.width(), self.evalTimeTABOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.evalTimeTABOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile)) 
        self.evalTimeTABOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.evalTimeTAB), ("Eval Time"))
        # Training Times
        image_profile2 = QtGui.QImage('figures/OptimisedTimeSeperateBars.png') #QImage object
        image_profile2 = image_profile2.scaled(self.timeOutputLABEL.width() ,self.timeOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.timeOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile2)) 
        self.timeOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.TimeTAB), ("Time"))
        # Recall
        image_profile3 = QtGui.QImage('figures/OptimisedRecallLineGraph.png') #QImage object
        image_profile3 = image_profile3.scaled(self.recallOutputLABEL.width() ,self.recallOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.recallOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile3)) 
        self.recallOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.RecallTAB), ("Recall"))


        image_profile4 = QtGui.QImage('figures/OptimisedPrecisionBoxPlots.png') #QImage object
        image_profile4 = image_profile4.scaled(self.precisionOutputLABEL.width() ,self.precisionOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.precisionOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile4)) 
        self.precisionOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.PrecisionTAB), ("Precision"))

        image_profile5 = QtGui.QImage('figures/Optimisedf1BoxPlots.png') #QImage object
        image_profile5 = image_profile5.scaled(self.f1OutputLABEL.width() ,self.f1OutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.f1OutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile5)) 
        self.f1OutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")

        image_profile6 = QtGui.QImage('figures/OptimisedBalancedAccuracyBoxPlots.png') #QImage object
        image_profile6 = image_profile6.scaled(self.balAccTabOutputLABEL.width() ,self.balAccTabOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.balAccTabOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile6)) 
        self.balAccTabOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")

    def BestPlots(self):
        #self.tabWidget.setTabVisible(self.tabWidget.indexOf(self.PrecisionTAB), False)
        self.tabWidget.setTabVisible(self.tabWidget.indexOf(self.F1TAB), False)
        self.tabWidget.setTabVisible(self.tabWidget.indexOf(self.balAccTAB), False)
        # Confusion Matrixf
        image_profile = QtGui.QImage('figures/BestMATRIX.png') #QImage object
        image_profile = image_profile.scaled(self.evalTimeTABOutputLABEL.width(), self.evalTimeTABOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.evalTimeTABOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile)) 
        self.evalTimeTABOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.evalTimeTAB), ("Confusion Mx"))
        # ROC Curve
        image_profile2 = QtGui.QImage('figures/BestROC.png') #QImage object
        image_profile2 = image_profile2.scaled(self.timeOutputLABEL.width() ,self.timeOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.timeOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile2)) 
        self.timeOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.TimeTAB), ("ROC"))
        

        # Prec Recall Curve
        image_profile3 = QtGui.QImage('figures/BestPrecRecallCurve.png') #QImage object
        image_profile3 = image_profile3.scaled(self.recallOutputLABEL.width() ,self.recallOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.recallOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile3)) 
        self.recallOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.RecallTAB), ("Precision Recall Curve"))

        # Metrics
        image_profile4 = QtGui.QImage('figures/BestMetrics.png') #QImage object
        image_profile4 = image_profile4.scaled(self.precisionOutputLABEL.width() ,self.precisionOutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        self.precisionOutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile4)) 
        self.precisionOutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.PrecisionTAB), ("Metric Performance"))

        #image_profile5 = QtGui.QImage('figures/Optimisedf1BoxPlots.png') #QImage object
        #image_profile5 = image_profile5.scaled(self.f1OutputLABEL.width() ,self.f1OutputLABEL.height(), aspectRatioMode=QtCore.Qt.AspectRatioMode.KeepAspectRatio, transformMode=QtCore.Qt.TransformationMode.SmoothTransformation) # To scale image for example and keep its Aspect Ration    
        #self.f1OutputLABEL.setPixmap(QtGui.QPixmap.fromImage(image_profile5)) 
        #self.f1OutputLABEL.setStyleSheet(f"qproperty-alignment: {int(QtCore.Qt.AlignmentFlag.AlignCenter)};")

    def handleStory(self):
        if self.PreprocessingCHECK.isChecked():
            self.modelNames, self.trainResults, self.oModelNames, self.oResults, self.size = us.fullToLive(self.trainingfile, self.targetfile)
        elif self.trainingSummariesCHECK.isChecked():
            self.modelNames, self.trainResults, self.oModelNames, self.oResults = us.modelSelection1File(self.trainingfile)
        else:
            self.modelNames, self.trainResults, self.oModelNames, self.oResults = us.modelSelectionNoProcessing(self.trainingfile, self.targetfile)

        print(self.trainResults)
        print(self.oModelNames[0])

        # Enable the output window
        self.graphOutputWIDGET.setEnabled(True)
        self.showPlots()
        self.setOutputStats()
        #self.OUTPUTstats.append('The Frequency of the feature sets is every: ' + str(self.size) + ' seconds')
    
    def updateOutput(self):
        if self.optimisationCHECK.isChecked():
            self.OptimisationPlots()
        if self.TrainingCHECK.isChecked():
            self.showPlots()
        if self.BestCHECK.isChecked():
            self.BestPlots()
        
    def setOutputStats(self):
        text = open('figures/outputText.txt').read()
        self.OUTPUTstats.setPlainText(text)
    
    def liveDetections(self):
        freq = int(self.freqINPUT .text())
        model = self.modelFileINPUT.text()
        try:
            us.liveAnalysis(modelFile=model, freq=freq)
            while True:
                time.sleep(300)
                text = open('figures/outputText.txt').read()
                self.OUTPUTstats.setPlainText(text)
        except:
            print("ERROR QUEEN")
