pipeline {
    agent any
    environment {

      MR_NUMBER = "${env.MR_NUMBER}"

    }
    stages {
        stage('Process value') {
            steps {
                script {
                    def value = params.$MR_NUMBER.split(',')
                    for (number in value) {
                        
                        echo "Processing number: ${number}"

                    }
                }
            }
        }
    }
}
