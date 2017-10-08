def configs = [
    [
        label: 'windows',
        toxenvs: ['py27', 'py33', 'py34', 'py35', 'py36'],
    ],
    [
        label: 'windows64',
        toxenvs: ['py27', 'py33', 'py34', 'py35', 'py36'],
    ],
]

def checkout_git(label) {
    def script = ""
    if (env.BRANCH_NAME.startsWith('PR-')) {
        script = """
        git clone --depth=1 https://github.com/pyca/pynacl
        cd pynacl
        git fetch origin +refs/pull/${env.CHANGE_ID}/merge:
        git checkout -qf FETCH_HEAD
        """
        bat script
    } else {
        checkout([
            $class: 'GitSCM',
            branches: [[name: "*/${env.BRANCH_NAME}"]],
            doGenerateSubmoduleConfigurations: false,
            extensions: [[
                $class: 'RelativeTargetDirectory',
                relativeTargetDir: 'pynacl'
            ]],
            submoduleCfg: [],
            userRemoteConfigs: [[
                'url': 'https://github.com/pyca/pynacl'
            ]]
        ])
    }
    bat """
        cd pynacl
        git rev-parse HEAD
    """
}
def build(toxenv, label) {
    try {
        timeout(time: 30, unit: 'MINUTES') {
            checkout_git(label)
            withEnv(["TOXENV=$toxenv"]) {
                def pythonPath = [
                    py27: "C:\\Python27\\python.exe",
                    py33: "C:\\Python33\\python.exe",
                    py34: "C:\\Python34\\python.exe",
                    py35: "C:\\Python35\\python.exe",
                    py36: "C:\\Python36\\python.exe"
                ]
                if (toxenv == "py35" || toxenv == "py36") {
                    libIncludePaths = [
                        "windows": [
                            "lib": "C:\\libsodium-1.0.15-msvc\\Win32\\Release\\v140\\static"
                        ],
                        "windows64": [
                            "lib": "C:\\libsodium-1.0.15-msvc\\x64\\Release\\v140\\static"
                        ]
                    ]
                } else {
                    libIncludePaths = [
                        "windows": [
                            "lib": "C:\\libsodium-1.0.15-msvc\\Win32\\Release\\v100\\static"
                        ],
                        "windows64": [
                            "lib": "C:\\libsodium-1.0.15-msvc\\x64\\Release\\v100\\static"
                        ]
                    ]
                }
                bat """
                    cd pynacl
                    @set PATH="C:\\Python27";"C:\\Python27\\Scripts";%PATH%
                    @set PYTHON="${pythonPath[toxenv]}"
                    @set PYNACL_SODIUM_LIBRARY_NAME=sodium
                    @set PYNACL_SODIUM_STATIC=1
                    @set SODIUM_INSTALL=system

                    @set INCLUDE="C:\\libsodium-1.0.15-msvc\\include";%INCLUDE%
                    @set LIB="${libIncludePaths[label]['lib']}";%LIB%
                    tox -r
                    IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%
                """
            }
        }
    } finally {
        deleteDir()
    }

}

def builders = [:]
for (config in configs) {
    def label = config["label"]
    def toxenvs = config["toxenvs"]

    for (_toxenv in toxenvs) {
        def toxenv = _toxenv

        def combinedName = "${label}-${toxenv}"
        builders[combinedName] = {
            node(label) {
                stage(combinedName) {
                    build(toxenv, label)
                }
            }
        }
    }
}

parallel builders
