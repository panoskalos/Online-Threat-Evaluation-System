# Online Threat Evaluation System

This project provides a simple web interface for uploading a screenshot of a web page and evaluating its threat level using the OpenAI API.

## Setup

## Configuration

`otes.php` requires an OpenAI API key. The preferred way is to set the environment variable `OPENAI_API_KEY` before running the script. When this variable is defined it will be used automatically.

For compatibility with previous versions, if `OPENAI_API_KEY` is not set the script will attempt to load `../init.php`, expecting it to define `$api_key`.

1. **Create `init.php` one directory above this repository**
   
   The application expects a file named `init.php` located *outside* of the repository in the parent directory. This keeps secrets out of version control. The file must define an `$api_key` variable containing your OpenAI API key:

   ```php
   <?php
   $api_key = 'your-openai-api-key';
   ```
   Save this file as `../init.php` relative to `otes.php`.

2. **PHP requirements**
   
   - PHP 7.4 or newer.
   - PHP extensions: `curl` and `fileinfo`.

3. **Directory permissions**
   
   When `otes.php` runs it creates an `uploads/` directory alongside the script (if it does not already exist) and writes a log file `otes_log.txt`. Ensure the web server user has write permissions to this repository so these files can be created and updated.

## JSON Response

The `evaluateThreat` function expects the API to return valid JSON. Successful
responses should contain the following fields:

- `phishing_likelihood_percent` – a number between 0 and 100 indicating the
  likelihood of the page being a phishing site.
- `justification` – a short explanation of the reasoning.

If the API cannot analyse the screenshot, it should respond with an `ERROR`
field describing what went wrong.

The main upload handler wraps this API output in another JSON object alongside
metadata about the uploaded file.

## Running

1. Start a local PHP server inside the repository directory:

   ```bash
   php -S localhost:8000
   ```

2. Open `upload.html` in your browser, for example `http://localhost:8000/upload.html`.

3. Upload a screenshot and submit the form. The request is sent to `otes.php`, which processes the image, calls the OpenAI API and returns a JSON response describing the phishing likelihood.