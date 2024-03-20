import csv
import argparse
import pandas as pd
import sys
from PIL import Image
import pygame
import os
import time
import frida 

# Initialize parser
parser = argparse.ArgumentParser(description="Process paths to two CSV files.")

# Add arguments for the CSV file paths
parser.add_argument("--training", type=str, help="Path to the training data csv labels.")
parser.add_argument("--validation", type=str, help="Path to the validation data csv labels.")
parser.add_argument("--training_images_path", type=str, help="Path to training images.")
parser.add_argument("--val_images_path", type=str, help="Path to training images.")


# Parse the arguments
args = parser.parse_args()

path1 = args.training
path2 = args.validation

image_folder1 = args.training_images_path
image_folder2 = args.val_images_path

# The name of the target process
TARGET_PROCESS = 'tiktok'

# JavaScript code to be injected
js_hook_code = """
Java.perform(function(){
    var clazz = Java.use("com.bef.effectsdk.message.MessageCenter")
    clazz.postMessage.implementation = function(i1,i2,i3,str) {
            // To relay this back to Python, we emit it as a message
            send(str);
            this.postMessage(i1,i2,i3,str);
        };

});
"""

current_image = ""
labels = []

# Callback to handle messages from JavaScript code
def on_message(message, data):
    global current_image
    global labels

    curr_img = current_image.split("/")[-2] + "/" + current_image.split("/")[-1]
    row = labels[labels["file"] == curr_img]
    
    age = row["age"].iloc[0]
    gender = row["gender"].iloc[0]
    race = row["race"].iloc[0]
    
    print(age)
    _min,_max = age.split("-")
    _min = int(_min)
    _max = int(_max)
    
    if message['type'] == 'send':
        prediction = message["payload"]
        preds = eval(prediction)
        base_infos = preds["base_infos"]

        face_count = int(preds["face_count"])
        
        #Check for a single face detected. 
        if len(base_infos) == 1 and face_count == 1:
            pred_age = base_infos[0]["age"]
            pred_gender = base_infos[0]["boy_prob"]

            with open("results.txt", "a+") as f:
                f.write(f"{curr_img}\t{age}\t{gender}\t{race}\t{pred_age}\t{pred_gender}\n")

    elif message['type'] == 'error':
        print(f"Error: {message['stack']}")


def load_csv_data(filepath):
    """
    Load data from a CSV file into a pandas DataFrame.

    Parameters:
    - filepath: str, path to the CSV file.

    Returns:
    - df: pandas DataFrame containing the loaded data.
    """

    # Define the columns to be loaded
    columns = ['file', 'age', 'gender', 'race', 'service_test']
    
    try:
        # Load the data
        df = pd.read_csv(filepath, usecols=columns)
        print("Data loaded successfully!")
        return df
    except FileNotFoundError:
        print(f"The file {filepath} was not found.")
    except pd.errors.EmptyDataError:
        print(f"The file {filepath} is empty.")
    except pd.errors.ParserError:
        print(f"Error parsing the file {filepath}.")
    except Exception as e:
        print(f"An error occurred: {e}")



def display_fullscreen_image_on_monitor(image_path, display_index=0, display_time=5):
    """
    Display an image in full screen mode on a specific monitor for a fixed time, centered on the screen.

    Parameters:
    - image_path: str, path to the image file.
    - display_index: int, index of the display monitor (0 for the first monitor, 1 for the second, etc.).
    - display_time: int, time in seconds to display the image.
    """
    global current_image

    current_image = image_path

    # Initialize Pygame
    pygame.init()

    # Check if the requested monitor index is available
    if display_index >= pygame.display.get_num_displays():
        raise ValueError(f"Display index {display_index} out of range. Only {pygame.display.get_num_displays()} displays detected.")

    # Set the window position to the monitor you want to use
    window_position = (pygame.display.Info().current_w * display_index, 0)
    os.environ['SDL_VIDEO_WINDOW_POS'] = f"{window_position[0]},{window_position[1]}"

    # Load the image using Pillow and convert it to a Pygame surface
    img = Image.open(image_path)
    img = img.convert('RGB')
    mode = img.size
    py_image = pygame.image.fromstring(img.tobytes(), mode, 'RGB')

    # Get the size of the display
    display_info = pygame.display.Info()
    screen_size = (display_info.current_w, display_info.current_h)

    # Create a window that will later be switched to full screen
    screen = pygame.display.set_mode(screen_size, pygame.NOFRAME)

    # Calculate the position to center the image
    x = (screen_size[0] - mode[0]) // 2
    y = (screen_size[1] - mode[1]) // 2

    # Display the image centered on the screen
    screen.blit(py_image, (x, y))
    pygame.display.flip()

    # Wait for the specified display time
    time.sleep(display_time)

    # Quit Pygame
    pygame.quit()


def display_all_images_in_folder(folder_path):
    # Define a list of possible image file extensions
    image_extensions = ['.jpg', '.jpeg', '.png', '.bmp', '.gif']

    # Get a list of files in the directory
    files = os.listdir(folder_path)

    # Filter out the list of files to only include images
    image_files = [file for file in files if any(file.lower().endswith(ext) for ext in image_extensions)]

    # Display each image in full screen
    for image_file in image_files:
        full_path = os.path.join(folder_path, image_file)
        print(f"Displaying {full_path}...")
        display_fullscreen_image_on_monitor(full_path)  # Assuming you've defined this function before
        print(f"Finished displaying {full_path}")





def main():    
    device = frida.get_usb_device()

    # pid = device.spawn([])
    session = device.attach(TARGET_PROCESS)

    # Inject JavaScript code
    script = session.create_script(js_hook_code)
    script.on('message', on_message)
    script.load()

    training_labels = load_csv_data(path1)
    testing_labels = load_csv_data(path2)
    
    global labels
    labels = training_labels

    display_all_images_in_folder(image_folder1)

if __name__ == "__main__":
    main()