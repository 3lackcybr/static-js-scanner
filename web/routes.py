# web/routes.py
import os
from flask import Blueprint, render_template, request, flash, redirect, url_for, session, current_app
from werkzeug.utils import secure_filename
from web.forms import ScanForm
from scanner.input_handler import InputHandler
from scanner.code_extractor import CodeExtractor
from scanner.parser import Parser
from scanner.core_engine import CoreAnalysisEngine
from scanner.report_generator import ReportGenerator

main_bp = Blueprint('main', __name__)

@main_bp.route('/', methods=['GET', 'POST'])
def index():
    form = ScanForm()
    if form.validate_on_submit():
        source = None
        if form.file_upload.data:
            file = form.file_upload.data
            filename = secure_filename(file.filename)
            upload_folder = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            source = filepath
        elif form.url_input.data:
            source = form.url_input.data.strip()
        
        if source:
            session['scan_source'] = source
            return redirect(url_for('main.scan'))
        else:
            flash('Please provide a file or URL.', 'warning')
    
    return render_template('index.html', form=form)

@main_bp.route('/scan')
def scan():
    source = session.get('scan_source')
    if not source:
        flash('No source provided.', 'error')
        return redirect(url_for('main.index'))
    
    try:
        input_handler = InputHandler()
        extractor = CodeExtractor()
        parser_obj = Parser()
        engine = CoreAnalysisEngine()
        
        # Get content (input_handler now returns combined content)
        content = input_handler.accept_input(source)
        
        # Extract JavaScript
        js_code = extractor.extract_javascript(content)
        
        if not extractor.is_javascript_present():
            return render_template('error.html',
                message="No JavaScript code found in the provided source.")
        
        # Parse and scan
        ast = parser_obj.parse_to_ast(js_code)
        code_lines = js_code.splitlines()
        vulnerabilities = engine.scan(ast, source, code_lines)
        
        # Generate report summary
        summary = ReportGenerator.generate_summary(vulnerabilities)
        vuln_dicts = ReportGenerator.to_dict_list(vulnerabilities)
        
        return render_template('scan_result.html',
                               vulnerabilities=vuln_dicts,
                               summary=summary,
                               source=source)
    
    except SyntaxError as e:
        return render_template('error.html', message=f"JavaScript syntax error: {e}")
    except Exception as e:
        return render_template('error.html', message=f"Scan failed: {e}")
    finally:
        session.pop('scan_source', None)
