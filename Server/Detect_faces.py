from __future__ import print_function
import click
import os
import re
import face_recognition.api as face_recognition
import multiprocessing
import itertools
import PIL.Image
import numpy as np
import ntpath

person_is_in_those_images = []

def is_face(file):
    basename = os.path.splitext(os.path.basename(file))[0]
    try:
        img = face_recognition.load_image_file(file)
        encodings = face_recognition.face_encodings(img)
    except FileNotFoundError:
        return False, -1

    if len(encodings) > 1:
        #click.echo("WARNING: More than one face found in {}. Only considering the first face.".format(file))
        return 2

    if len(encodings) == 0:
        #click.echo("WARNING: No faces found in {}. Ignoring file.".format(file))
        return 0

    return 1


def scan_known_people(known_people_folder):
    known_names = []
    known_face_encodings = []

    for file in image_files_in_folder(known_people_folder):
        basename = ntpath.basename(file)
        img = face_recognition.load_image_file(file)
        encodings = face_recognition.face_encodings(img)

        if len(encodings) == 1:  # one face
            known_names.append(basename)
            known_face_encodings.append(encodings[0])

    return known_names, known_face_encodings


def print_result(filename, name, distance, show_distance=False):
    global person_is_in_those_images
    if show_distance:
        #print("{},{},{}".format(filename, name, distance))
        person_is_in_those_images.append(name)


def test_image(image_to_check, known_names, known_face_encodings, tolerance=0.6, show_distance=False):
    unknown_image = face_recognition.load_image_file(image_to_check)

    # Scale down image if it's giant so things run a little faster
    if max(unknown_image.shape) > 1600:
        pil_img = PIL.Image.fromarray(unknown_image)
        pil_img.thumbnail((1600, 1600), PIL.Image.LANCZOS)
        unknown_image = np.array(pil_img)

    unknown_encodings = face_recognition.face_encodings(unknown_image)
    for unknown_encoding in unknown_encodings:
        distances = face_recognition.face_distance(known_face_encodings, unknown_encoding)

        result = list(distances <= tolerance)

        if True in result:
            [print_result(image_to_check, name, distance, show_distance) for is_match, name, distance in zip(result, known_names, distances) if is_match]
        #else:
        #    print_result(image_to_check, "unknown_person", None, show_distance)

    #if not unknown_encodings:
        # print out fact that no faces were found in image
    #    print_result(image_to_check, "no_persons_found", None, show_distance)


def image_files_in_folder(folder):
    return [os.path.join(folder, f) for f in os.listdir(folder) if re.match(r'.*\.(jpg|jpeg|png)', f, flags=re.I)]


def process_images_in_process_pool(images_to_check, known_names, known_face_encodings, number_of_cpus, tolerance, show_distance):
    if number_of_cpus == -1:
        processes = None
    else:
        processes = number_of_cpus

    # macOS will crash due to a bug in libdispatch if you don't use 'forkserver'
    context = multiprocessing
    if "forkserver" in multiprocessing.get_all_start_methods():
        context = multiprocessing.get_context("forkserver")

    pool = context.Pool(processes=processes)

    function_parameters = zip(
        images_to_check,
        itertools.repeat(known_names),
        itertools.repeat(known_face_encodings),
        itertools.repeat(tolerance),
        itertools.repeat(show_distance)
    )

    pool.starmap(test_image, function_parameters)



def detect_people(known_people_folder, image_to_check, cpus=4, tolerance=0.6, show_distance=True):
    global person_is_in_those_images
    person_is_in_those_images = []

    known_names, known_face_encodings = scan_known_people(known_people_folder)

    if os.path.isdir(image_to_check):
            process_images_in_process_pool(image_files_in_folder(image_to_check), known_names, known_face_encodings, cpus, tolerance, show_distance)
    else:
        test_image(image_to_check, known_names, known_face_encodings, tolerance, show_distance)

    return person_is_in_those_images

if __name__ == '__main__':
    person =  'C:\\Users\\almog\\AppData\\Local\\Programs\\Python\\Python37\\programming\\Detection_app\\Server\\DB\\almog\\2020-03-04 15;34;23,237716\\Trump.png'
    gallery = r"C:\Users\almog\AppData\Local\Programs\Python\Python37\programming\Detection_app\Server\DB\almog\2020-03-04 13;46;44,989033\2020-03-04 13;46;51,169000_Gallery"
    correct_images = detect_people(gallery, person)
    print(correct_images)
    #print(is_face("Images\Check_People\\Test_Trump.jpg"))