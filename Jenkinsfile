pipeline {
    agent any
    environment {

      MR_NUMBER = "test,demo,new"

    }
    stages {
        stage('Process value') {
            steps {
                script {
                    def value = $MR_NUMBER.split(',')
                    for (number in value) {
                        
                        echo "Processing number: ${number}"

                    }
                }
            }
        }
    }
}
