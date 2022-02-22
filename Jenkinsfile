@Library('mdblp-library') _
def builderImage
pipeline {
    agent any
    stages {
        stage('Initialization') {
            steps {
                script {
                    utils.initPipeline()
                    if(env.GIT_COMMIT == null) {
                        // git commit id must be a 40 characters length string (lower case or digits)
                        env.GIT_COMMIT = "f".multiply(40)
                    }
                    env.RUN_ID = UUID.randomUUID().toString()
                    docker.image('docker.ci.diabeloop.eu/ci-toolbox').inside() {
                        env.version = sh (
                            script: 'release-helper get-version',
                            returnStdout: true
                        ).trim().toUpperCase()
                    }
                    env.APP_VERSION = env.version
                    env.buildImage = "docker.ci.diabeloop.eu/go-build:1.17"
                }
            }
        }
        stage('Build ') {
            agent {
                docker {
                    image env.buildImage
                }
            }
            steps {
                script {
                    sh "$WORKSPACE/build.sh"
                }
            }
        }
        stage('Test ') {
            steps {
                echo 'start mongo to serve as a testing db'
                sh 'docker network create shorelinetest${RUN_ID} && docker run --rm -d --net=shorelinetest${RUN_ID} --name=mongo4shoreline${RUN_ID} mongo:4.2'
                script {
                    docker.image(env.buildImage).inside("--net=shorelinetest${RUN_ID}") {
                        sh "TIDEPOOL_STORE_ADDRESSES=mongo4shoreline${RUN_ID}:27017  TIDEPOOL_STORE_DATABASE=shoreline_test $WORKSPACE/test.sh"
                    }
                }
            }
            post {
                always {
                    sh 'docker stop mongo4shoreline${RUN_ID} && docker network rm shorelinetest${RUN_ID}'
                    junit 'test-report.xml'
                    cobertura coberturaReportFile: 'coverage.xml'
                    archiveArtifacts 'coverReport.html'
                }
            }
        }
        stage('Package') {
            steps {
                pack()
            }
        }
        stage('Documentation') {
            steps {
                genDocumentation()
            }
        }
        stage('Publish') {
            when { branch "dblp" }
            steps {
                publish()
            }
        }
    }
    post {
        always {
            script {
                utils.closePipeline()
            }
        }
    }
}
