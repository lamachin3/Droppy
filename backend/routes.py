from flask import Flask, render_template, request, redirect, url_for

def init_routes(app):
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/config", methods=["GET"])
    def config():
        modules = ["obfuscation", "anti_debug", "anti_emulation", "shellcode_loader", "injection"]
        return render_template("dropper_config.html", modules=modules)

    @app.route("/build", methods=["POST"])
    def build_dropper():
        selected_modules = request.form.getlist("modules")
        output_filename = request.form.get("output_filename", "dropper.exe")

        print(f"Selected Modules: {selected_modules}")
        print(f"Output Filename: {output_filename}")

        return redirect(url_for("result"))

    @app.route("/result")
    def result():
        message = "Success!"
        error_message = None
        previous_droppers = ["dropper_1.exe", "dropper_2.exe"]

        return render_template("result.html", message=message, error_message=error_message, previous_droppers=previous_droppers)
