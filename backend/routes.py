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
        # Initialize a single dictionary to store all data
        dropper_config = extract_form_data()

        # Process preprocessing macros and placeholder options
        process_dropper_config(dropper_config)

        # Handle file upload
        dropper_config['shellcode'] = handle_shellcode_upload(request.files)
        if not dropper_config['shellcode'] and dropper_config.get('shellcode_text'):
            cleaned = re.findall(r'0x[0-9A-Fa-f]{2}', dropper_config.get('shellcode_text'))
            dropper_config['shellcode'] = ', '.join(cleaned)

        # Validate shellcode
        if not dropper_config.get("shellcode"):
            messages = {"error": "Empty shellcode"}
            query_string = urlencode({"messages": str(messages)})
            redirect_url = f"/config?{query_string}"
            return redirect(redirect_url)

        # Call build_dropper with the form data
        build_dropper(dropper_config)

        return redirect(url_for('index'))
