# Local AI Models Directory

This directory is used to store the GGUF format models for local AI analysis.

## Recommended Models

1. **Mistral 7B (Recommended)**
   - Download from: https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF
   - Recommended file: `mistral-7b-instruct-v0.2.Q4_K_M.gguf`
   - Size: ~4GB
   - Best balance of performance and resource usage

2. **Llama 2 7B (Alternative)**
   - Download from: https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF
   - Recommended file: `llama-2-7b-chat.Q4_K_M.gguf`
   - Size: ~4GB

## Installation Steps

1. Download your chosen model file from the links above
2. Place the .gguf file in this directory
3. No renaming is necessary - the application will find the model automatically

## Model Selection

The application will automatically use:
1. Mistral 7B if available (preferred)
2. Llama 2 if Mistral is not found
3. Will prompt for download if no model is found

## Requirements

- Minimum 8GB RAM
- ~5GB free disk space
- CPU with AVX2 support (most modern CPUs)

## Troubleshooting

If you encounter issues:
1. Ensure you downloaded the Q4_K_M version of the model
2. Check that the file extension is .gguf
3. Verify you have enough free RAM
4. Try running with --debug flag for more information 