pipeline {
    agent any
    
    environment {
        MR_NUMBER1 = "${env.MR_NUMBER}"
    }
    
    stages {
        stage('Process value') {
            steps {
                script {
                    def value = env.MR_NUMBER1.split(',')
                    for (number in value) {
                        echo "Processing number: ${number}"
                    }
                }
            }
        }
    }
}
