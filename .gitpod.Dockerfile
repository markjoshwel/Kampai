FROM gitpod/workspace-full

RUN pyenv update \
    && pyenv install 3.10.5 \
    && pyenv global 3.10.5 \
    && python3 -m pip install --no-cache-dir --upgrade pip \
    && python3 -m pip install --no-cache-dir --upgrade \
        setuptools wheel virtualenv \
    && sudo rm -rf /tmp/*

USER gitpod
RUN python3 -m pip install --no-cache-dir --upgrade wheel
RUN python3 -m pip install --no-cache-dir --upgrade poetry==1.2.0b2
RUN python3 -m poetry config virtualenvs.in-project true
