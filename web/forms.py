# web/forms.py
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SubmitField
from wtforms.validators import Optional, URL, ValidationError
from urllib.parse import urlparse

def validate_url(form, field):
    """Custom validator to ensure URL has a scheme and is valid."""
    if field.data:
        url = field.data.strip()
        parsed = urlparse(url)
        # Add 'https' scheme if missing
        if not parsed.scheme:
            url = 'https://' + url
            field.data = url
            parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            raise ValidationError('Invalid URL scheme. Use http or https.')

class ScanForm(FlaskForm):
    file_upload = FileField('Upload JavaScript/HTML/PHP File', validators=[
        Optional(),
        FileAllowed(['js', 'html', 'php', 'txt'], 'Only .js, .html, .php, .txt files allowed')
    ])
    url_input = StringField('Or Enter URL', validators=[Optional(), validate_url])
    submit = SubmitField('Scan Now')
