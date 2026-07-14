import os
from flask import Blueprint, render_template, request, flash, redirect, url_for
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, SubmitField
from wtforms.validators import Optional

from scanner.input_handler import InputHandler
from scanner.code_extractor import CodeExtractor
from scanner.core_engine import CoreAnalysisEngine
from scanner.report_generator import ReportGenerator

main_bp = Blueprint('main', __name__)

class ScanForm(FlaskForm):
    file_upload = FileField('File Upload', validators=[Optional()])
    url_input = StringField('URL', validators=[Optional()])
    folder_path = StringField('Folder Path', validators=[Optional()])
    submit = SubmitField('Start Scan')

@main_bp.route('/', methods=['GET', 'POST'])
def index():
    form = ScanForm()
    if form.validate_on_submit():
        upload = form.file_upload.data
        url = form.url_input.data.strip() if form.url_input.data else ''
        folder = form.folder_path.data.strip() if form.folder_path.data else ''

        if upload:
            filename = secure_filename(upload.filename)
            filepath = os.path.join('uploads', filename)
            upload.save(filepath)
            return process_scan(filepath, filename)

        if url:
            return process_scan(url, url)

        if folder and os.path.isdir(folder):
            return process_folder(folder)

        flash('Please provide a file, URL, or folder path.', 'danger')
        return redirect(url_for('main.index'))

    return render_template('index.html', form=form)

def run_single_scan(source, label):
    handler = InputHandler()
    result = handler.accept_input(source)
    if result is None:
        return None

    extractor = CodeExtractor()
    parts = extractor.extract_with_origins(result['html'], result.get('external_js', []))

    engine = CoreAnalysisEngine()
    return engine.scan(parts, label)

def process_scan(source, label):
    try:
        vulns = run_single_scan(source, label)
        if vulns is None:
            flash(f'Source is a directory: {label}', 'warning')
            return redirect(url_for('main.index'))
    except (ValueError, ConnectionError) as e:
        return render_template('error.html', message=str(e))

    summary = ReportGenerator.generate_summary(vulns)
    vuln_list = ReportGenerator.to_dict_list(vulns)

    return render_template('scan_result.html', source=label, summary=summary,
                           vulnerabilities=vuln_list, skipped_files=[])

def process_folder(folder):
    handler = InputHandler()
    files = handler.get_files_from_folder(folder)
    if not files:
        flash('No supported files found in folder.', 'warning')
        return redirect(url_for('main.index'))

    all_vulns = []
    skipped = []
    for filepath in files:
        try:
            vulns = run_single_scan(filepath, filepath)
            if vulns is not None:
                all_vulns.extend(vulns)
        except Exception:
            skipped.append(filepath)

    summary = ReportGenerator.generate_summary(all_vulns)
    vuln_list = ReportGenerator.to_dict_list(all_vulns)

    return render_template('scan_result.html', source=folder, summary=summary,
                           vulnerabilities=vuln_list, skipped_files=skipped)
