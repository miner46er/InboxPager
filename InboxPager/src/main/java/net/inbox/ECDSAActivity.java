package net.inbox;

import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import net.inbox.ecdsa.ECDSAHelper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Objects;

public class ECDSAActivity extends AppCompatActivity {
    static final int RESULT_CODE = 2834;
    static final int ECDSA_SIGN_REQUEST_CODE = 135;
    static final int ECDSA_VERIFY_REQUEST_CODE = 182;
    static final int PICK_PRIVATE_KEY_REQUEST_CODE = 135;
    static final int PICK_PUBLIC_KEY_REQUEST_CODE = 182;

    TextView buttonSign;
    TextView buttonRemove;
    TextView buttonFinish;
    TextView keyInput;
    TextView keyChooser;
    TextView keyGenerator;
    TextView signPreview;

    String originalMessage;

    ECDSAHelper ecdsaHelper;

    int requestCode;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.digital_signature);

        originalMessage = getIntent().getStringExtra("message-data");
        System.out.println(originalMessage);
        requestCode = getIntent().getIntExtra("request-code", 0);

        ecdsaHelper = new ECDSAHelper();

        buttonSign = findViewById(R.id.tv_sign);
        buttonRemove = findViewById(R.id.tv_remove);
        buttonFinish = findViewById(R.id.tv_finish);

        keyChooser = findViewById(R.id.b_key_import);
        keyGenerator = findViewById(R.id.b_key_generate);
        keyInput = findViewById(R.id.et_digital_signature);

        signPreview = findViewById(R.id.tv_signature_preview);

        if (requestCode == ECDSA_VERIFY_REQUEST_CODE) {
            keyGenerator.setVisibility(View.GONE);

            buttonSign.setText(R.string.digsig_verify);

            TextView resultTitle = findViewById(R.id.ecdsa_result_title);
            resultTitle.setText(R.string.digsig_header_verify);
        }

        buttonSign.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                if (requestCode == ECDSA_SIGN_REQUEST_CODE) {
                    if (!ecdsaHelper.setPrivateKey(keyInput.toString())) {
                        signPreview.setText(R.string.digsig_key_invalid);
                        signPreview.setTextColor(Color.RED);
                        return;
                    }

                    signPreview.setText(ecdsaHelper.signSignatureOnly(originalMessage));
                } else if (requestCode == ECDSA_VERIFY_REQUEST_CODE) {
                    if (!ecdsaHelper.setPublicKey(keyInput.toString())) {
                        signPreview.setText(R.string.digsig_key_invalid);
                        signPreview.setTextColor(Color.RED);
                        return;
                    }

                    boolean verifyResult = ecdsaHelper.verify(originalMessage);

                    if (verifyResult) {
                        signPreview.setText(R.string.digsig_signature_verified);
                        signPreview.setTextColor(Color.GREEN);
                    } else {
                        signPreview.setText(R.string.digsig_signature_invalid);
                        signPreview.setTextColor(Color.RED);
                    }
                }
            }
        });

        buttonRemove.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                signPreview.setText("");
            }
        });

        buttonFinish.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                Intent intent = getIntent();
                intent.putExtra("signed-message", ecdsaHelper.sign(originalMessage));
                setResult(RESULT_CODE, intent);
                finish();
            }
        });

        keyChooser.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.setType("*/*");
                intent.addCategory(Intent.CATEGORY_OPENABLE);

                if (intent.resolveActivity(getPackageManager()) != null) {
                    int pickRequestCode = PICK_PRIVATE_KEY_REQUEST_CODE;
                    if (requestCode == ECDSA_VERIFY_REQUEST_CODE) {
                        pickRequestCode = PICK_PUBLIC_KEY_REQUEST_CODE;
                    }
                    startActivityForResult(intent, pickRequestCode);
                }
            }
        });

        keyGenerator.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                ecdsaHelper.generateKeyPair();
                keyInput.setText(ecdsaHelper.getPrivateKey());

                String path = Environment.getExternalStorageDirectory().toString() + "/InboxPager/ECDSA/keys";
                File myDir = new File(path);

                if (!myDir.exists()) {
                    myDir.mkdirs();
                }

                File privateKeyFile = new File (myDir, "key");
                File publicKeyFile = new File (myDir, "key.pub");

                if (privateKeyFile.exists ()) {
                    privateKeyFile.delete();
                }
                if (publicKeyFile.exists ()) {
                    publicKeyFile.delete();
                }

                try {
                    FileOutputStream privateKeyOutputStream = new FileOutputStream(privateKeyFile);
                    byte[] privateKeyBytes = ecdsaHelper.getPrivateKey().getBytes();
                    privateKeyOutputStream.write(privateKeyBytes);
                    privateKeyOutputStream.close();

                    FileOutputStream publicKeyOutputStream = new FileOutputStream(publicKeyFile);
                    byte[] publicKeyBytes = ecdsaHelper.getPublicKey().getBytes();
                    publicKeyOutputStream.write(publicKeyBytes);
                    publicKeyOutputStream.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (resultCode == RESULT_OK) {
            if (requestCode == PICK_PRIVATE_KEY_REQUEST_CODE) {
                Uri keyUri = data.getData();

                try {
                    String key = readTextFromUri(keyUri);

                    keyInput.setText(key);
                    ecdsaHelper.setPrivateKey(key);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else if (requestCode == PICK_PUBLIC_KEY_REQUEST_CODE) {
                Uri keyUri = data.getData();

                try {
                    String key = readTextFromUri(keyUri);

                    keyInput.setText(key);
                    ecdsaHelper.setPublicKey(key);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private String readTextFromUri(Uri uri) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        try (InputStream inputStream = getContentResolver().openInputStream(uri);
             BufferedReader reader = new BufferedReader(
                     new InputStreamReader(Objects.requireNonNull(inputStream)))) {
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
        }
        return stringBuilder.toString();
    }
}
