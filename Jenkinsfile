@Library('mdblp-library') _
def builderImage
pipeline {
    agent {
        label 'blp'
    }
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
        stage('Build') {
            agent {
                docker {
                    image env.buildImage
                    label 'blp'
                }
            }
            steps {
                script {
                    withCredentials ([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                        sh 'git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"'
                        sh "$WORKSPACE/build.sh"
                        sh 'git config --global --unset url."https://${GITHUB_TOKEN}@github.com/".insteadOf'
                    }
                }
            }
        }
        stage('Test ') {
            steps {
                echo 'start mongo to serve as a testing db'
                sh 'docker network create shorelinetest${RUN_ID} && docker run --rm -d --net=shorelinetest${RUN_ID} --name=mongo4shoreline${RUN_ID} mongo:4.2'
                script {
                    docker.image(env.buildImage).inside("--net=shorelinetest${RUN_ID}") {
                        withCredentials ([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                            sh 'git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"'
                            sh "TIDEPOOL_STORE_ADDRESSES=mongo4shoreline${RUN_ID}:27017  TIDEPOOL_STORE_DATABASE=shoreline_test $WORKSPACE/test.sh"
                            sh 'git config --global --unset url."https://${GITHUB_TOKEN}@github.com/".insteadOf'
                        }
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
                withCredentials ([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                    pack()
                }
            }
        }
        stage('Documentation') {
            steps {
                withCredentials ([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                    genDocumentation()
                }
            }
        }
        stage('Publish') {
            when { branch "dblp" }
            steps {
                withCredentials ([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                    publish()
                }
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
