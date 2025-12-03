package com.example.mfa.simple

import android.Manifest
import android.app.AlertDialog
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.gson.Gson
import java.io.IOException
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.Executor

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var btnConnectBT: Button
    private lateinit var btnBiometrics: Button
    private lateinit var btnPIN: Button
    private lateinit var btnSend: Button

    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bluetoothSocket: BluetoothSocket? = null
    private var connectedDevice: BluetoothDevice? = null
    private var isAuthenticated = false
    private var authMethod = "none"

    private val hc05Uuid = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")
    private val requestPermissionsCode = 100

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    private val gson = Gson()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initializeViews()
        checkPermissions()
        initializeBluetooth()
        initializeBiometric()

        btnConnectBT.setOnClickListener { connectToHC05() }
        btnBiometrics.setOnClickListener { authenticateWithBiometrics() }
        btnPIN.setOnClickListener { authenticateWithPIN() }
        btnSend.setOnClickListener { sendJSONData() }
    }

    private fun initializeViews() {
        statusText = findViewById(R.id.statusText)
        btnConnectBT = findViewById(R.id.btnConnectBT)
        btnBiometrics = findViewById(R.id.btnBiometrics)
        btnPIN = findViewById(R.id.btnPIN)
        btnSend = findViewById(R.id.btnSend)
    }

    private fun checkPermissions() {
        val permissions = mutableListOf<String>()
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.BLUETOOTH_SCAN)
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.BLUETOOTH_CONNECT)
            }
        } else {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.BLUETOOTH)
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_ADMIN) != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.BLUETOOTH_ADMIN)
            }
        }
        
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }

        if (permissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, permissions.toTypedArray(), requestPermissionsCode)
        }
    }

    private fun initializeBluetooth() {
        val bluetoothManager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter
        if (bluetoothAdapter == null) {
            updateStatus("Bluetooth not supported")
            btnConnectBT.isEnabled = false
        } else {
            if (!bluetoothAdapter!!.isEnabled) {
                updateStatus("Please enable Bluetooth")
            } else {
                updateStatus("Bluetooth ready")
            }
        }
    }

    private fun initializeBiometric() {
        executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    runOnUiThread {
                        updateStatus("Biometric error: $errString")
                        isAuthenticated = false
                    }
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    runOnUiThread {
                        isAuthenticated = true
                        authMethod = "biometric"
                        updateStatus("Biometric authentication successful")
                        btnSend.isEnabled = true
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    runOnUiThread {
                        updateStatus("Biometric authentication failed")
                        isAuthenticated = false
                    }
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_title))
            .setSubtitle(getString(R.string.biometric_subtitle))
            // Note: setNegativeButtonText() cannot be used when DEVICE_CREDENTIAL is allowed
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()
    }

    private fun connectToHC05() {
        if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            updateStatus("Bluetooth is not enabled")
            return
        }

        updateStatus("Scanning for HC-05...")
        
        val pairedDevices = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                bluetoothAdapter!!.bondedDevices
            } else {
                emptySet()
            }
        } else {
            bluetoothAdapter!!.bondedDevices
        }

        var hc05Found = false
        for (device in pairedDevices) {
            val deviceName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                    device.name
                } else {
                    null
                }
            } else {
                device.name
            }
            
            if (deviceName != null && (deviceName.contains("HC-05", ignoreCase = true) || 
                deviceName.contains("HC05", ignoreCase = true))) {
                hc05Found = true
                connectToDevice(device)
                break
            }
        }

        if (!hc05Found) {
            updateStatus("HC-05 not found. Please pair it first.")
            Toast.makeText(this, "Please pair HC-05 device first in Bluetooth settings", Toast.LENGTH_LONG).show()
        }
    }

    private fun connectToDevice(device: BluetoothDevice) {
        updateStatus("Connecting to ${device.name}...")
        
        Thread {
            try {
                val socket = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                        device.createRfcommSocketToServiceRecord(hc05Uuid)
                    } else {
                        null
                    }
                } else {
                    device.createRfcommSocketToServiceRecord(hc05Uuid)
                }

                if (socket != null) {
                    bluetoothAdapter?.cancelDiscovery()
                    socket.connect()
                    bluetoothSocket = socket
                    connectedDevice = device
                    
                    runOnUiThread {
                        updateStatus("Connected to ${device.name}")
                        btnConnectBT.isEnabled = false
                    }
                }
            } catch (e: IOException) {
                runOnUiThread {
                    updateStatus("Connection failed: ${e.message}")
                }
                try {
                    bluetoothSocket?.close()
                } catch (_: IOException) {
                    // Ignore
                }
                bluetoothSocket = null
            }
        }.start()
    }

    private fun authenticateWithBiometrics() {
        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                biometricPrompt.authenticate(promptInfo)
            }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                updateStatus("No biometric hardware available")
            }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                updateStatus("Biometric hardware unavailable")
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                updateStatus("No biometric enrolled. Use PIN instead.")
            }
            else -> {
                updateStatus("Biometric authentication not available")
            }
        }
    }

    private fun authenticateWithPIN() {
        val input = EditText(this)
        input.hint = "Enter PIN"
        input.inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
        input.setPadding(50, 20, 50, 20)

        val dialog = AlertDialog.Builder(this)
            .setTitle("PIN Authentication")
            .setView(input)
            .setPositiveButton("OK") { _, _ ->
                val pin = input.text.toString()
                if (pin.isNotEmpty()) {
                    // Simple PIN validation (in production, use secure storage)
                    if (pin.length >= 4) {
                        isAuthenticated = true
                        authMethod = "pin"
                        updateStatus("PIN authentication successful")
                        btnSend.isEnabled = true
                    } else {
                        updateStatus("PIN must be at least 4 digits")
                    }
                } else {
                    updateStatus("PIN cannot be empty")
                }
            }
            .setNegativeButton("Cancel", null)
            .create()

        dialog.show()
    }

    private fun sendJSONData() {
        if (!isAuthenticated) {
            updateStatus("Please authenticate first")
            return
        }

        if (bluetoothSocket == null || !bluetoothSocket!!.isConnected) {
            updateStatus("Not connected to HC-05")
            return
        }

        val jsonData = mapOf(
            "auth" to authMethod,
            "timestamp" to System.currentTimeMillis()
        )

        val jsonString = gson.toJson(jsonData)
        
        Thread {
            try {
                val outputStream: OutputStream? = bluetoothSocket?.outputStream
                if (outputStream != null) {
                    outputStream.write(jsonString.toByteArray())
                    outputStream.flush()
                    
                    runOnUiThread {
                        updateStatus("JSON sent: $jsonString")
                        Toast.makeText(this, "Data sent successfully", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    runOnUiThread {
                        updateStatus("Failed to get output stream")
                    }
                }
            } catch (e: IOException) {
                runOnUiThread {
                    updateStatus("Send failed: ${e.message}")
                }
            }
        }.start()
    }

    private fun updateStatus(message: String) {
        statusText.text = getString(R.string.status_template, message)
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            bluetoothSocket?.close()
        } catch (_: IOException) {
            // Ignore
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == requestPermissionsCode) {
            if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                updateStatus("Permissions granted")
            } else {
                updateStatus("Permissions denied")
            }
        }
    }
}
